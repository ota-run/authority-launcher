//                █████
//               ░░███
//       ██████  ███████    ██████
//      ███░░███░░░███░    ░░░░░███
//     ░███ ░███  ░███      ███████
//     ░███ ░███  ░███ ███ ███░░███
//      ░░██████   ░░█████ ░░████████
//       ░░░░░░     ░░░░░   ░░░░░░░░
//
//   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
//   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//   If you need additional information or have any questions, please email: os@ota.run

//! Feature-gated reference peer for hosted adversarial pressure only.
//!
//! This binary uses fixed public test keys. It is not a production broker, authority issuer, or
//! supported operator surface.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use ota_authority_protocol::{
    ATTESTATION_RESPONSE_DOMAIN_V1, AUTHORIZATION_DECISION_DOMAIN_V1,
    AUTHORIZATION_REQUEST_DOMAIN_V1, AuthorizationDecision, AuthorizationDecisionPayload,
    AuthorizationRequest, BROKER_BINDING_IDENTITY_DOMAIN_V1, BrokerChallenge, CHALLENGE_REQUEST,
    LEASE_CONSUME_DOMAIN_V1, LEASE_CONSUME_RESPONSE_DOMAIN_V1, LEASE_ISSUANCE_DOMAIN_V1,
    LauncherAttestationPayload, LeaseConsumeRequest, LeaseConsumeResponsePayload,
    LeaseConsumeState, PreparedLeasePayload, SignedBrokerMessage, SignedLauncherAttestation,
    message_identity,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AUTHORITY_ID: &str = "platform-release-authority";
const BROKER_DESCRIPTOR: RawFd = 4;
const OTA_DESCRIPTOR: RawFd = 3;
const SIGNING_SEED: [u8; 32] = [9_u8; 32];
const KEY_ID: &str = "broker-2026-01";

#[derive(Debug, Parser)]
#[command(name = "ota-authority-pressure-peer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install fixed test-only launcher and Core binding configuration.
    Provision {
        #[arg(long)]
        ota_binary: PathBuf,
        #[arg(long)]
        run_uid: u32,
        #[arg(long)]
        run_gid: u32,
        #[arg(long)]
        run_home: PathBuf,
    },
    /// Execute one real launcher/Core protocol scenario.
    Execute {
        #[arg(long)]
        launcher: PathBuf,
        #[arg(long, value_enum)]
        scenario: Scenario,
        #[arg(last = true, required = true)]
        ota_args: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Scenario {
    Live,
    Expired,
    Revoked,
    WrongScope,
    Replay,
}

fn main() -> ExitCode {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("ota-authority-pressure-peer: root is required for the pressure boundary");
        return ExitCode::from(1);
    }
    let result = match Cli::parse().command {
        Command::Provision {
            ota_binary,
            run_uid,
            run_gid,
            run_home,
        } => provision(&ota_binary, run_uid, run_gid, &run_home),
        Command::Execute {
            launcher,
            scenario,
            ota_args,
        } => execute(&launcher, scenario, &ota_args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ota-authority-pressure-peer: {error}");
            ExitCode::from(1)
        }
    }
}

fn provision(ota_binary: &Path, run_uid: u32, run_gid: u32, run_home: &Path) -> Result<u8, String> {
    for path in [Path::new("/etc/ota"), Path::new("/var/lib/ota")] {
        fs::create_dir_all(path)
            .map_err(|error| format!("failed to create protected store: {error}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("failed to protect authority store: {error}"))?;
    }
    let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let placeholder_identity = format!("sha256:{}", "a".repeat(64));
    let mut binding = json!({
        "identity": "",
        "authority_id": AUTHORITY_ID,
        "broker_id": "platform-crossing-broker",
        "origin": "https://broker.example.internal",
        "server_name": "broker.example.internal",
        "protocol_version": ota_authority_protocol::PROTOCOL_VERSION_V1,
        "transport_authentication": {
            "kind": "mtls",
            "trust_bundle_identity": placeholder_identity,
            "credential_source_identity": "launcher:pressure-session/v1"
        },
        "credential_delivery": {
            "kind": "launcher_session_fd",
            "descriptor": OTA_DESCRIPTOR,
            "session_audience": "ota-crossing-broker"
        },
        "broker_verifiers": [
            { "key_id": KEY_ID, "algorithm": "ed25519", "public_key": public_key }
        ],
        "attestation": {
            "issuer": "runner-launcher",
            "audience": "ota-crossing-broker",
            "trust_bundle_identity": placeholder_identity,
            "verifiers": [
                { "key_id": KEY_ID, "algorithm": "ed25519", "public_key": public_key }
            ],
            "maximum_age_seconds": 180,
            "maximum_clock_skew_seconds": 5,
            "key_rotation_overlap_seconds": 120,
            "mandatory_protocol_claims": [
                "authenticated_origin",
                "authority_mounts",
                "binding_identity",
                "challenge_nonce_commitment",
                "channel_delivery",
                "invocation_id",
                "runner_principal",
                "semantic_scope_identity",
                "work_unit_identity"
            ],
            "required_administrator_claims": []
        },
        "message_domains": {
            "challenge_request": ota_authority_protocol::CHALLENGE_REQUEST_DOMAIN_V1,
            "attestation_response": ATTESTATION_RESPONSE_DOMAIN_V1,
            "authorization_request": AUTHORIZATION_REQUEST_DOMAIN_V1,
            "authorization_decision": AUTHORIZATION_DECISION_DOMAIN_V1,
            "lease_issuance": LEASE_ISSUANCE_DOMAIN_V1,
            "lease_consume": LEASE_CONSUME_DOMAIN_V1,
            "lease_consume_response": LEASE_CONSUME_RESPONSE_DOMAIN_V1
        },
        "maximum_approval_wait_seconds": 120,
        "minimum_post_approval_freshness_seconds": 30,
        "maximum_lease_seconds": 300
    });
    let binding_identity = message_identity(BROKER_BINDING_IDENTITY_DOMAIN_V1, &binding)
        .map_err(|error| format!("failed to identify pressure binding: {error}"))?;
    binding["identity"] = Value::String(binding_identity);
    write_protected_json(
        Path::new("/etc/ota/crossing-brokers.json"),
        &json!({ "schema_version": 1, "bindings": [binding] }),
        0o644,
    )?;
    write_protected_json(
        Path::new("/etc/ota/authority-launcher.json"),
        &json!({
            "schema_version": 1,
            "ota_binary": ota_binary,
            "run_as": { "uid": run_uid, "gid": run_gid },
            "environment": {
                "HOME": run_home,
                "LANG": "C.UTF-8",
                "LOGNAME": "ota-runner",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "USER": "ota-runner"
            },
            "sessions": [{
                "authority_id": AUTHORITY_ID,
                "broker_session_descriptor": BROKER_DESCRIPTOR,
                "expected_peer": { "uid": 0, "gid": 0 }
            }]
        }),
        0o600,
    )?;
    Ok(0)
}

fn write_protected_json(path: &Path, value: &Value, mode: u32) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize protected config: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|error| format!("failed to create protected config: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("failed to persist protected config: {error}"))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("failed to publish protected config: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("failed to protect config permissions: {error}"))?;
    Ok(())
}

fn execute(launcher: &Path, scenario: Scenario, ota_args: &[String]) -> Result<u8, String> {
    let (mut broker, launcher_session) = UnixStream::pair()
        .map_err(|error| format!("failed to create launcher session: {error}"))?;
    broker
        .set_read_timeout(Some(Duration::from_secs(30)))
        .and_then(|_| broker.set_write_timeout(Some(Duration::from_secs(5))))
        .map_err(|error| format!("failed to bound pressure session: {error}"))?;
    let source_descriptor = launcher_session.as_raw_fd();
    let mut command = ProcessCommand::new(launcher);
    command
        .arg("run")
        .arg("--authority-id")
        .arg(AUTHORITY_ID)
        .arg("--")
        .args(ota_args);
    unsafe {
        command.pre_exec(move || {
            if source_descriptor != BROKER_DESCRIPTOR {
                if libc::dup2(source_descriptor, BROKER_DESCRIPTOR) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(source_descriptor);
            }
            let flags = libc::fcntl(BROKER_DESCRIPTOR, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(BROKER_DESCRIPTOR, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start protected launcher: {error}"))?;
    drop(launcher_session);
    if let Err(error) = serve_session(&mut broker, scenario) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for protected launcher: {error}"))?;
    Ok(status.code().unwrap_or(1).clamp(0, u8::MAX as i32) as u8)
}

fn serve_session(stream: &mut UnixStream, scenario: Scenario) -> Result<(), String> {
    let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
    let now = OffsetDateTime::now_utc();
    let challenge: BrokerChallenge = read_json_frame(stream)?;
    if challenge.message_kind != CHALLENGE_REQUEST {
        return Err(String::from("Core did not begin with a challenge request"));
    }
    let attestation = sign_attestation(&signing_key, &challenge, now)?;
    write_json_frame(stream, &attestation)?;

    let request: AuthorizationRequest = read_json_frame(stream)?;
    let request_identity =
        message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &request)
            .map_err(|error| format!("failed to identify authorization request: {error}"))?;
    let decision_time = if matches!(scenario, Scenario::Expired) {
        now - time::Duration::seconds(120)
    } else {
        now
    };
    let mut decision_payload = AuthorizationDecisionPayload {
        message_kind: String::from("authorization_decision"),
        request_identity,
        binding_identity: request.binding_identity.clone(),
        authority_id: request.authority_id.clone(),
        attestation_identity: request.attestation_identity.clone(),
        challenge_nonce_commitment: request.challenge_nonce_commitment.clone(),
        work_unit_identity: request.work_unit_identity.clone(),
        contract_identity: request.contract_identity.clone(),
        semantic_scope_identity: request.semantic_scope_identity.clone(),
        decision: AuthorizationDecision::Allowed,
        approval_reference: Some(String::from("pressure:approved")),
        broker_revision: 1,
        issued_at: formatted(decision_time)?,
        expires_at: formatted(decision_time + time::Duration::seconds(60))?,
    };
    if matches!(scenario, Scenario::WrongScope) {
        decision_payload.semantic_scope_identity = format!("sha256:{}", "f".repeat(64));
    }
    let decision = sign_message(
        &signing_key,
        AUTHORIZATION_DECISION_DOMAIN_V1,
        decision_payload,
    )?;
    let decision_identity =
        message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), &decision)
            .map_err(|error| format!("failed to identify authorization decision: {error}"))?;
    write_json_frame(stream, &decision)?;
    if matches!(scenario, Scenario::Expired | Scenario::WrongScope) {
        return Ok(());
    }

    let lease = sign_message(
        &signing_key,
        LEASE_ISSUANCE_DOMAIN_V1,
        PreparedLeasePayload {
            message_kind: String::from("lease_issuance"),
            authorization_decision_identity: decision_identity,
            binding_identity: request.binding_identity.clone(),
            authority_id: request.authority_id.clone(),
            attestation_identity: request.attestation_identity.clone(),
            challenge_nonce_commitment: request.challenge_nonce_commitment.clone(),
            work_unit_identity: request.work_unit_identity.clone(),
            contract_identity: request.contract_identity.clone(),
            semantic_scope_identity: request.semantic_scope_identity.clone(),
            runner_principal: request.runner_principal.clone(),
            broker_revision: 1,
            lease_sequence: 1,
            issued_at: formatted(now)?,
            expires_at: formatted(now + time::Duration::seconds(60))?,
        },
    )?;
    let lease_identity = message_identity(LEASE_ISSUANCE_DOMAIN_V1.as_bytes(), &lease)
        .map_err(|error| format!("failed to identify prepared lease: {error}"))?;
    write_json_frame(stream, &lease)?;

    let consume: LeaseConsumeRequest = read_json_frame(stream)?;
    if consume.lease_identity != lease_identity {
        return Err(String::from(
            "Core consumed a lease other than the prepared lease",
        ));
    }
    let consume_identity = message_identity(LEASE_CONSUME_DOMAIN_V1.as_bytes(), &consume)
        .map_err(|error| format!("failed to identify consume request: {error}"))?;
    let state = match scenario {
        Scenario::Live => LeaseConsumeState::Consumed,
        Scenario::Revoked => LeaseConsumeState::Revoked,
        Scenario::Replay => LeaseConsumeState::AlreadyConsumed,
        Scenario::Expired | Scenario::WrongScope => unreachable!("scenario returned earlier"),
    };
    let response = sign_message(
        &signing_key,
        LEASE_CONSUME_RESPONSE_DOMAIN_V1,
        LeaseConsumeResponsePayload {
            message_kind: String::from("lease_consume_response"),
            consume_request_identity: consume_identity,
            binding_identity: consume.binding_identity.clone(),
            lease_identity: consume.lease_identity.clone(),
            challenge_nonce_commitment: consume.challenge_nonce_commitment.clone(),
            work_unit_identity: consume.work_unit_identity.clone(),
            crossing_transaction_id: consume.crossing_transaction_id.clone(),
            crossing_transaction_identity: consume.crossing_transaction_identity.clone(),
            state,
            broker_revision: 1,
            consumed_at: formatted(OffsetDateTime::now_utc())?,
        },
    )?;
    write_json_frame(stream, &response)
}

fn sign_attestation(
    signing_key: &SigningKey,
    challenge: &BrokerChallenge,
    now: OffsetDateTime,
) -> Result<SignedLauncherAttestation, String> {
    let payload = LauncherAttestationPayload {
        message_kind: String::from("attestation_response"),
        binding_identity: challenge.binding_identity.clone(),
        challenge_nonce_commitment: challenge.nonce_commitment.clone(),
        invocation_id: String::from("pressure-invocation"),
        work_unit_identity: challenge.work_unit_identity.clone(),
        semantic_scope_identity: challenge.semantic_scope_identity.clone(),
        runner_principal: String::from("ota-runner"),
        channel_delivery: String::from("launcher_session_fd"),
        authenticated_origin: String::from("https://broker.example.internal"),
        authority_mounts: vec![String::from("authority-mount-profile:v1")],
        issuer: String::from("runner-launcher"),
        audience: String::from("ota-crossing-broker"),
        issued_at: formatted(now)?,
        expires_at: formatted(now + time::Duration::seconds(180))?,
    };
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|error| format!("failed to canonicalize attestation: {error}"))?;
    let signature = signing_key.sign(&ota_authority_protocol::domain_separated(
        ATTESTATION_RESPONSE_DOMAIN_V1.as_bytes(),
        &canonical,
    ));
    Ok(SignedLauncherAttestation {
        payload,
        key_id: String::from(KEY_ID),
        algorithm: String::from("ed25519"),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn sign_message<T: Serialize>(
    signing_key: &SigningKey,
    domain: &str,
    payload: T,
) -> Result<SignedBrokerMessage<T>, String> {
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|error| format!("failed to canonicalize broker message: {error}"))?;
    let signature = signing_key.sign(&ota_authority_protocol::domain_separated(
        domain.as_bytes(),
        &canonical,
    ));
    Ok(SignedBrokerMessage {
        payload,
        key_id: String::from(KEY_ID),
        algorithm: String::from("ed25519"),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn formatted(value: OffsetDateTime) -> Result<String, String> {
    value
        .format(&Rfc3339)
        .map_err(|error| format!("failed to format pressure timestamp: {error}"))
}

fn write_json_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize pressure frame: {error}"))?;
    let frame = ota_authority_protocol::encode_frame(&payload)
        .map_err(|error| format!("failed to frame pressure message: {error}"))?;
    stream
        .write_all(&frame)
        .map_err(|error| format!("failed to write pressure frame: {error}"))
}

fn read_json_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, String> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("failed to read pressure frame length: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > ota_authority_protocol::MAX_FRAME_BYTES {
        return Err(String::from("pressure frame exceeds the protocol bound"));
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|error| format!("failed to read pressure frame: {error}"))?;
    serde_json::from_slice(&payload)
        .map_err(|error| format!("failed to parse pressure frame: {error}"))
}
