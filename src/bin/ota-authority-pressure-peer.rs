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

//! Feature-gated reference peer for hosted adversarial pressure only.
//!
//! This binary uses fixed public test keys. It is not a production broker, authority issuer, or
//! supported operator surface.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use ota_authority_protocol::{
    ATTESTATION_RESPONSE_DOMAIN_V2, AUTHORIZATION_DECISION_DOMAIN_V1,
    AUTHORIZATION_REQUEST_DOMAIN_V1, AuthorizationDecision, AuthorizationDecisionPayload,
    AuthorizationRequest, BROKER_BINDING_IDENTITY_DOMAIN_V2, BrokerChallenge, CHALLENGE_REQUEST,
    LEASE_CONSUME_DOMAIN_V1, LEASE_CONSUME_RESPONSE_DOMAIN_V1, LEASE_CONSUMPTION_QUERY_DOMAIN_V1,
    LEASE_CONSUMPTION_STATUS_DOMAIN_V1, LEASE_ISSUANCE_DOMAIN_V1, LauncherAttestationPayloadV2,
    LeaseConsumeRequest, LeaseConsumeResponsePayload, LeaseConsumeState, LeaseConsumptionQuery,
    LeaseConsumptionStatus, LeaseConsumptionStatusPayload, PROTECTED_LAUNCHER_PROFILE_ID_V1,
    PreparedLeasePayload, RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2,
    RUNTIME_BOUNDARY_SCHEMA_VERSION_V1, RuntimeBoundaryAttestation, RuntimeBoundaryObservation,
    RuntimeBoundaryObservationName, RuntimeBoundaryObservationState,
    RuntimeBoundarySemanticIdentityPosture, SignedBrokerMessage, SignedLauncherAttestationV2,
    message_identity, runtime_boundary_profile_by_id, runtime_boundary_profile_identity,
    sha256_identity,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const AUTHORITY_ID: &str = "platform-release-authority";
const BROKER_DESCRIPTOR: RawFd = 4;
const OTA_DESCRIPTOR: RawFd = 3;
const BROKER_SIGNING_SEED: [u8; 32] = [9_u8; 32];
const ATTESTOR_SIGNING_SEED: [u8; 32] = [10_u8; 32];
const BROKER_KEY_ID: &str = "broker-2026-01";
const ATTESTOR_KEY_ID: &str = "attestor-2026-01";
const LAUNCHER_SESSION_BINDING_LABEL: &[u8] = b"ota-authority-pressure-launcher-session/v2";
const RECOVERY_STATE_PATH: &str = "/var/lib/ota/pressure-consumption-recovery.json";
const CATCH_ALL_STATE_PATH: &str = "/var/lib/ota/pressure-catch-all-invocation.json";
const LATE_APPROVAL_STATE_PATH: &str = "/var/lib/ota/pressure-late-approval.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConsumptionRecovery {
    consume_request_identity: String,
    consume_request: LeaseConsumeRequest,
    consume_response: SignedBrokerMessage<LeaseConsumeResponsePayload>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCatchAllInvocation {
    semantic_scope_identity: String,
    work_unit_identity: String,
}

#[derive(Debug, Deserialize)]
struct PressureLauncherConfig {
    run_as: PressureRunAs,
    environment: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PressureRunAs {
    uid: u32,
    gid: u32,
}

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
    Unavailable,
    PendingTimeout,
    PendingCancelled,
    PendingLateApproval,
    InsufficientPreWaitFreshness,
    PendingAmbiguous,
    ConsumeResponseLost,
    RecoveryConsumed,
    CatchAllFirst,
    CatchAllSecond,
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
    if let Err(error) = fs::remove_file(RECOVERY_STATE_PATH)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!("failed to clear pressure recovery state: {error}"));
    }
    if let Err(error) = fs::remove_file(CATCH_ALL_STATE_PATH)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!("failed to clear catch-all pressure state: {error}"));
    }
    if let Err(error) = fs::remove_file(LATE_APPROVAL_STATE_PATH)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!(
            "failed to clear late-approval pressure state: {error}"
        ));
    }
    let binding = build_pressure_binding()?;
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
                "PATH": "/usr/lib/ota-authority/pressure-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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

fn build_pressure_binding() -> Result<Value, String> {
    let broker_signing_key = SigningKey::from_bytes(&BROKER_SIGNING_SEED);
    let attestor_signing_key = SigningKey::from_bytes(&ATTESTOR_SIGNING_SEED);
    let broker_public_key = URL_SAFE_NO_PAD.encode(broker_signing_key.verifying_key().to_bytes());
    let attestor_public_key =
        URL_SAFE_NO_PAD.encode(attestor_signing_key.verifying_key().to_bytes());
    let placeholder_identity = format!("sha256:{}", "a".repeat(64));
    let profile = runtime_boundary_profile_by_id(PROTECTED_LAUNCHER_PROFILE_ID_V1)
        .ok_or_else(|| String::from("pressure runtime-boundary profile is unavailable"))?;
    let profile_identity = runtime_boundary_profile_identity(&profile).map_err(|error| {
        format!("failed to identify pressure runtime-boundary profile: {error}")
    })?;
    let mut binding = json!({
        "schema_version": 2,
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
            { "key_id": BROKER_KEY_ID, "algorithm": "ed25519", "public_key": broker_public_key }
        ],
        "attestation": {
            "protocol_version": RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2,
            "profile_id": PROTECTED_LAUNCHER_PROFILE_ID_V1,
            "profile_identity": profile_identity,
            "attestor_kind": "protected_launcher",
            "adapter": "launcher_session_peer/v1",
            "launcher_session_binding_identity": sha256_identity(LAUNCHER_SESSION_BINDING_LABEL),
            "issuer": "runner-launcher",
            "audience": "ota-crossing-broker",
            "trust_bundle_identity": placeholder_identity,
            "verifiers": [
                { "key_id": ATTESTOR_KEY_ID, "algorithm": "ed25519", "public_key": attestor_public_key }
            ],
            "maximum_age_seconds": 180,
            "maximum_clock_skew_seconds": 5,
            "key_rotation_overlap_seconds": 120
        },
        "message_domains": {
            "challenge_request": ota_authority_protocol::CHALLENGE_REQUEST_DOMAIN_V1,
            "attestation_response": ATTESTATION_RESPONSE_DOMAIN_V2,
            "authorization_request": AUTHORIZATION_REQUEST_DOMAIN_V1,
            "authorization_decision": AUTHORIZATION_DECISION_DOMAIN_V1,
            "lease_issuance": LEASE_ISSUANCE_DOMAIN_V1,
            "lease_consume": LEASE_CONSUME_DOMAIN_V1,
            "lease_consume_response": LEASE_CONSUME_RESPONSE_DOMAIN_V1,
            "lease_consumption_query": LEASE_CONSUMPTION_QUERY_DOMAIN_V1,
            "lease_consumption_status": LEASE_CONSUMPTION_STATUS_DOMAIN_V1
        },
        "maximum_approval_wait_seconds": 2,
        "minimum_post_approval_freshness_seconds": 30,
        "maximum_lease_seconds": 300
    });
    let binding_identity = message_identity(BROKER_BINDING_IDENTITY_DOMAIN_V2, &binding)
        .map_err(|error| format!("failed to identify pressure binding: {error}"))?;
    binding["identity"] = Value::String(binding_identity);
    Ok(binding)
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
    if let Err(error) = serve_session(&mut broker, scenario, child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for protected launcher: {error}"))?;
    Ok(status.code().unwrap_or(1).clamp(0, u8::MAX as i32) as u8)
}

fn serve_session(
    stream: &mut UnixStream,
    scenario: Scenario,
    child_pid: u32,
) -> Result<(), String> {
    if matches!(scenario, Scenario::Unavailable) {
        stream
            .shutdown(Shutdown::Both)
            .map_err(|error| format!("failed to close unavailable pressure session: {error}"))?;
        eprintln!("pressure-peer-scenario: unavailable");
        return Ok(());
    }
    let signing_key = SigningKey::from_bytes(&BROKER_SIGNING_SEED);
    let attestor_signing_key = SigningKey::from_bytes(&ATTESTOR_SIGNING_SEED);
    let now = OffsetDateTime::now_utc();
    let challenge: BrokerChallenge = read_json_frame(stream)?;
    if challenge.message_kind != CHALLENGE_REQUEST {
        return Err(String::from("Core did not begin with a challenge request"));
    }
    let attestation_lifetime_seconds = if matches!(scenario, Scenario::InsufficientPreWaitFreshness)
    {
        31
    } else {
        180
    };
    let attestation = sign_attestation(
        &attestor_signing_key,
        &challenge,
        child_pid,
        now,
        attestation_lifetime_seconds,
    )?;
    write_json_frame(stream, &attestation)?;

    let next = read_json_frame::<Value>(stream);
    if matches!(scenario, Scenario::InsufficientPreWaitFreshness) {
        return match next {
            Ok(_) => Err(String::from(
                "Core requested authorization with attestation that cannot cover the bounded wait",
            )),
            Err(error)
                if error.contains("failed to fill whole buffer")
                    || error.contains("Connection reset by peer") =>
            {
                eprintln!(
                    "pressure-peer-scenario: insufficient-pre-wait-freshness required-seconds=32 attestation-seconds=31 authorization-request=false"
                );
                Ok(())
            }
            Err(error) => Err(format!(
                "Core did not close the insufficient-freshness session cleanly: {error}"
            )),
        };
    }
    let next = next?;
    let request: AuthorizationRequest =
        if next.get("message_kind").and_then(Value::as_str) == Some("lease_consumption_query") {
            if !matches!(scenario, Scenario::RecoveryConsumed) {
                return Err(String::from(
                    "Core sent a recovery query outside the recovery pressure scenario",
                ));
            }
            let query: LeaseConsumptionQuery = serde_json::from_value(next)
                .map_err(|error| format!("Core sent a malformed recovery query: {error}"))?;
            serve_consumption_recovery(stream, &signing_key, &query)?;
            read_json_frame(stream)?
        } else {
            serde_json::from_value(next)
                .map_err(|error| format!("Core sent a malformed authorization request: {error}"))?
        };
    let request_identity =
        message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &request)
            .map_err(|error| format!("failed to identify authorization request: {error}"))?;
    verify_catch_all_invocation(scenario, &request)?;
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
    if matches!(
        scenario,
        Scenario::PendingTimeout
            | Scenario::PendingCancelled
            | Scenario::PendingLateApproval
            | Scenario::PendingAmbiguous
    ) {
        decision_payload.decision = AuthorizationDecision::Pending;
        decision_payload.approval_reference = None;
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
    if matches!(
        scenario,
        Scenario::PendingTimeout
            | Scenario::PendingCancelled
            | Scenario::PendingLateApproval
            | Scenario::PendingAmbiguous
    ) {
        match scenario {
            Scenario::PendingTimeout => {
                std::thread::sleep(Duration::from_secs(3));
                eprintln!("pressure-peer-scenario: pending-timeout");
            }
            Scenario::PendingCancelled => {
                // SAFETY: the PID belongs to the launcher process started by this pressure peer.
                if unsafe { libc::kill(child_pid as i32, libc::SIGINT) } != 0 {
                    return Err(format!(
                        "failed to interrupt pending pressure invocation: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                eprintln!("pressure-peer-scenario: pending-cancelled");
            }
            Scenario::PendingLateApproval => {
                // SAFETY: the PID belongs to the launcher process started by this pressure peer.
                if unsafe { libc::kill(child_pid as i32, libc::SIGINT) } != 0 {
                    return Err(format!(
                        "failed to interrupt late-approval pressure invocation: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                wait_for_linux_process_terminal(child_pid, Duration::from_secs(2))?;
                let late_time = OffsetDateTime::now_utc();
                let mut late_payload = decision.payload.clone();
                late_payload.decision = AuthorizationDecision::Allowed;
                late_payload.approval_reference = Some(String::from("pressure:late-approval"));
                late_payload.broker_revision += 1;
                late_payload.issued_at = formatted(late_time)?;
                late_payload.expires_at = formatted(late_time + time::Duration::seconds(60))?;
                let late_decision =
                    sign_message(&signing_key, AUTHORIZATION_DECISION_DOMAIN_V1, late_payload)?;
                write_protected_json(
                    Path::new(LATE_APPROVAL_STATE_PATH),
                    &serde_json::to_value(&late_decision).map_err(|error| {
                        format!("failed to encode late-approval pressure state: {error}")
                    })?,
                    0o600,
                )?;
                let delivery_error = match write_json_frame(stream, &late_decision) {
                    Ok(()) => {
                        return Err(String::from(
                            "terminal cancelled launcher session accepted a late decision",
                        ));
                    }
                    Err(error) => error,
                };
                eprintln!(
                    "pressure-peer-scenario: late-approval-after-terminal-cancellation session-closed=true delivery-refused=true ({delivery_error})"
                );
            }
            Scenario::PendingAmbiguous => {
                let mut conflicting_payload = decision.payload.clone();
                conflicting_payload.broker_revision = 2;
                let conflicting = sign_message(
                    &signing_key,
                    AUTHORIZATION_DECISION_DOMAIN_V1,
                    conflicting_payload,
                )?;
                write_json_frame(stream, &conflicting)?;
                eprintln!("pressure-peer-scenario: pending-ambiguous");
            }
            _ => unreachable!("pending scenario matched above"),
        }
        return Ok(());
    }
    if matches!(scenario, Scenario::Expired | Scenario::WrongScope) {
        eprintln!(
            "pressure-peer-scenario: {}",
            match scenario {
                Scenario::Expired => "expired-decision",
                Scenario::WrongScope => "wrong-scope-decision",
                _ => unreachable!("scenario returned earlier"),
            }
        );
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
        Scenario::Live | Scenario::CatchAllFirst | Scenario::CatchAllSecond => {
            LeaseConsumeState::Consumed
        }
        Scenario::Revoked => LeaseConsumeState::Revoked,
        Scenario::Replay => LeaseConsumeState::AlreadyConsumed,
        Scenario::ConsumeResponseLost | Scenario::RecoveryConsumed => LeaseConsumeState::Consumed,
        Scenario::Expired
        | Scenario::WrongScope
        | Scenario::Unavailable
        | Scenario::PendingTimeout
        | Scenario::PendingCancelled
        | Scenario::PendingLateApproval
        | Scenario::InsufficientPreWaitFreshness
        | Scenario::PendingAmbiguous => unreachable!("scenario returned earlier"),
    };
    let response = sign_message(
        &signing_key,
        LEASE_CONSUME_RESPONSE_DOMAIN_V1,
        LeaseConsumeResponsePayload {
            message_kind: String::from("lease_consume_response"),
            consume_request_identity: consume_identity.clone(),
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
    if matches!(scenario, Scenario::ConsumeResponseLost) {
        write_protected_json(
            Path::new(RECOVERY_STATE_PATH),
            &serde_json::to_value(StoredConsumptionRecovery {
                consume_request_identity: consume_identity,
                consume_request: consume,
                consume_response: response,
            })
            .map_err(|error| format!("failed to encode pressure recovery state: {error}"))?,
            0o600,
        )?;
        stream
            .shutdown(Shutdown::Both)
            .map_err(|error| format!("failed to end uncertain consume session: {error}"))?;
        eprintln!("pressure-peer-scenario: consume-response-lost");
        return Ok(());
    }
    write_json_frame(stream, &response)?;
    eprintln!(
        "pressure-peer-scenario: {}",
        match scenario {
            Scenario::Live => "consumed",
            Scenario::CatchAllFirst => "catch-all-first-consumed",
            Scenario::CatchAllSecond => "catch-all-second-distinct-work-unit-consumed",
            Scenario::Revoked => "revoked-consume",
            Scenario::Replay => "already-consumed",
            Scenario::RecoveryConsumed => "recovery-consumed-then-fresh-consumed",
            Scenario::ConsumeResponseLost => unreachable!("scenario returned before response"),
            Scenario::Expired
            | Scenario::WrongScope
            | Scenario::Unavailable
            | Scenario::PendingTimeout
            | Scenario::PendingCancelled
            | Scenario::PendingLateApproval
            | Scenario::InsufficientPreWaitFreshness
            | Scenario::PendingAmbiguous => unreachable!("scenario returned earlier"),
        }
    );
    Ok(())
}

fn serve_consumption_recovery(
    stream: &mut UnixStream,
    signing_key: &SigningKey,
    query: &LeaseConsumptionQuery,
) -> Result<(), String> {
    let bytes = fs::read(RECOVERY_STATE_PATH)
        .map_err(|error| format!("failed to read pressure recovery state: {error}"))?;
    let stored: StoredConsumptionRecovery = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse pressure recovery state: {error}"))?;
    if query.message_kind != "lease_consumption_query"
        || query.lease_identity != stored.consume_request.lease_identity
        || query.consume_request_identity != stored.consume_request_identity
        || query.original_work_unit_identity != stored.consume_request.work_unit_identity
        || query.crossing_transaction_id != stored.consume_request.crossing_transaction_id
        || query.crossing_transaction_identity
            != stored.consume_request.crossing_transaction_identity
    {
        return Err(String::from(
            "Core recovery query does not bind the stored uncertain consume intent",
        ));
    }
    let query_identity = message_identity(LEASE_CONSUMPTION_QUERY_DOMAIN_V1.as_bytes(), query)
        .map_err(|error| format!("failed to identify recovery query: {error}"))?;
    let status = sign_message(
        signing_key,
        LEASE_CONSUMPTION_STATUS_DOMAIN_V1,
        LeaseConsumptionStatusPayload {
            message_kind: String::from("lease_consumption_status"),
            query_identity,
            binding_identity: query.binding_identity.clone(),
            attestation_identity: query.attestation_identity.clone(),
            recovery_challenge_nonce_commitment: query.recovery_challenge_nonce_commitment.clone(),
            recovery_work_unit_identity: query.recovery_work_unit_identity.clone(),
            lease_identity: query.lease_identity.clone(),
            consume_request_identity: query.consume_request_identity.clone(),
            original_work_unit_identity: query.original_work_unit_identity.clone(),
            crossing_transaction_id: query.crossing_transaction_id.clone(),
            crossing_transaction_identity: query.crossing_transaction_identity.clone(),
            broker_revision: stored.consume_response.payload.broker_revision,
            observed_at: formatted(OffsetDateTime::now_utc())?,
            status: LeaseConsumptionStatus::Consumed {
                consume_response: Box::new(stored.consume_response),
            },
        },
    )?;
    write_json_frame(stream, &status)?;
    eprintln!("pressure-peer-scenario: recovered-consumed-status");
    Ok(())
}

fn verify_catch_all_invocation(
    scenario: Scenario,
    request: &AuthorizationRequest,
) -> Result<(), String> {
    match scenario {
        Scenario::CatchAllFirst => write_protected_json(
            Path::new(CATCH_ALL_STATE_PATH),
            &serde_json::to_value(StoredCatchAllInvocation {
                semantic_scope_identity: request.semantic_scope_identity.clone(),
                work_unit_identity: request.work_unit_identity.clone(),
            })
            .map_err(|error| format!("failed to encode catch-all pressure state: {error}"))?,
            0o600,
        ),
        Scenario::CatchAllSecond => {
            let bytes = fs::read(CATCH_ALL_STATE_PATH)
                .map_err(|error| format!("failed to read catch-all pressure state: {error}"))?;
            let first: StoredCatchAllInvocation = serde_json::from_slice(&bytes)
                .map_err(|error| format!("failed to parse catch-all pressure state: {error}"))?;
            if request.semantic_scope_identity != first.semantic_scope_identity {
                return Err(String::from(
                    "catch-all invocation changed semantic scope between executions",
                ));
            }
            if request.work_unit_identity == first.work_unit_identity {
                return Err(String::from(
                    "catch-all invocation reused the first work-unit identity",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn wait_for_linux_process_terminal(child_pid: u32, timeout: Duration) -> Result<(), String> {
    if !Path::new("/proc/self/stat").is_file() {
        return Err(String::from(
            "terminal cancellation pressure requires Linux process state",
        ));
    }
    let status_path = PathBuf::from(format!("/proc/{child_pid}/stat"));
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(&status_path) {
            Ok(status) => {
                let state = status
                    .rsplit_once(") ")
                    .and_then(|(_, fields)| fields.chars().next())
                    .ok_or_else(|| {
                        String::from("failed to parse cancelled launcher process state")
                    })?;
                if state == 'Z' {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "failed to inspect cancelled launcher process state: {error}"
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(String::from(
                "cancelled launcher did not reach a terminal process state",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn sign_attestation(
    signing_key: &SigningKey,
    challenge: &BrokerChallenge,
    launcher_pid: u32,
    now: OffsetDateTime,
    lifetime_seconds: i64,
) -> Result<SignedLauncherAttestationV2, String> {
    let profile = runtime_boundary_profile_by_id(PROTECTED_LAUNCHER_PROFILE_ID_V1)
        .ok_or_else(|| String::from("pressure runtime-boundary profile is unavailable"))?;
    let profile_identity = runtime_boundary_profile_identity(&profile).map_err(|error| {
        format!("failed to identify pressure runtime-boundary profile: {error}")
    })?;
    let observations = observe_protected_runtime_boundary(&profile, launcher_pid)?;
    let payload = LauncherAttestationPayloadV2 {
        message_kind: String::from("attestation_response"),
        attestation_protocol_version: String::from(RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2),
        binding_identity: challenge.binding_identity.clone(),
        challenge_nonce_commitment: challenge.nonce_commitment.clone(),
        invocation_id: String::from("pressure-invocation"),
        work_unit_identity: challenge.work_unit_identity.clone(),
        semantic_scope_identity: challenge.semantic_scope_identity.clone(),
        runner_principal: String::from("ota-runner"),
        channel_delivery: String::from("launcher_session_fd"),
        authenticated_origin: String::from("https://broker.example.internal"),
        authority_mounts: vec![String::from("authority-mount-profile:v2")],
        runtime_boundary: RuntimeBoundaryAttestation {
            schema_version: RUNTIME_BOUNDARY_SCHEMA_VERSION_V1,
            profile_id: String::from(PROTECTED_LAUNCHER_PROFILE_ID_V1),
            profile_identity,
            attestor_kind: ota_authority_protocol::RuntimeBoundaryAttestorKind::ProtectedLauncher,
            attestor_instance_identity: sha256_identity(&signing_key.verifying_key().to_bytes()),
            launcher_session_binding_identity: sha256_identity(LAUNCHER_SESSION_BINDING_LABEL),
            observations,
        },
        issuer: String::from("runner-launcher"),
        audience: String::from("ota-crossing-broker"),
        issued_at: formatted(now)?,
        expires_at: formatted(now + time::Duration::seconds(lifetime_seconds))?,
    };
    let canonical = serde_jcs::to_vec(&payload)
        .map_err(|error| format!("failed to canonicalize attestation: {error}"))?;
    let signature = signing_key.sign(&ota_authority_protocol::domain_separated(
        ATTESTATION_RESPONSE_DOMAIN_V2.as_bytes(),
        &canonical,
    ));
    Ok(SignedLauncherAttestationV2 {
        payload,
        key_id: String::from(ATTESTOR_KEY_ID),
        algorithm: String::from("ed25519"),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

fn observe_protected_runtime_boundary(
    profile: &ota_authority_protocol::RuntimeBoundaryProfileDefinition,
    launcher_pid: u32,
) -> Result<Vec<RuntimeBoundaryObservation>, String> {
    let config_bytes = fs::read("/etc/ota/authority-launcher.json")
        .map_err(|error| format!("failed to read protected launcher config: {error}"))?;
    let config: PressureLauncherConfig = serde_json::from_slice(&config_bytes)
        .map_err(|error| format!("failed to parse protected launcher config: {error}"))?;
    let ota_pid = wait_for_single_child_pid(launcher_pid, Duration::from_secs(2))?;
    let status = fs::read_to_string(format!("/proc/{ota_pid}/status"))
        .map_err(|error| format!("failed to inspect protected Ota principal: {error}"))?;
    verify_process_principal(&status, &config.run_as)?;

    let observed_environment = fs::read(format!("/proc/{ota_pid}/environ"))
        .map_err(|error| format!("failed to inspect protected Ota environment: {error}"))?;
    let observed_environment = parse_process_environment(&observed_environment)?;
    if observed_environment != config.environment {
        return Err(String::from(
            "protected Ota process inherited environment outside launcher policy",
        ));
    }
    for name in config.environment.keys() {
        let uppercase = name.to_ascii_uppercase();
        if ["TOKEN", "SECRET", "CREDENTIAL", "PRIVATE_KEY", "BROKER"]
            .iter()
            .any(|fragment| uppercase.contains(fragment))
        {
            return Err(String::from(
                "launcher policy exposes credential-shaped environment state",
            ));
        }
    }

    let ota_session_fd = 3;
    verify_unnamed_unix_stream(ota_pid, ota_session_fd)?;
    let fdinfo = fs::read_to_string(format!("/proc/{ota_pid}/fdinfo/{ota_session_fd}"))
        .map_err(|error| format!("failed to inspect protected Ota descriptor flags: {error}"))?;
    let descriptor_flags = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .ok_or_else(|| String::from("protected Ota descriptor flags are unavailable"))?;
    if descriptor_flags & libc::O_CLOEXEC as u32 == 0 {
        return Err(String::from(
            "protected Ota session descriptor is inheritable",
        ));
    }

    for path in [
        "/etc/ota/crossing-brokers.json",
        "/etc/ota/authority-launcher.json",
        "/var/lib/ota",
    ] {
        if target_can_access(Path::new(path), libc::W_OK, &config.run_as)? {
            return Err(format!("protected authority path is writable: {path}"));
        }
    }
    if target_can_access(
        Path::new("/usr/lib/ota-authority/bin/ota-authority-pressure-peer"),
        libc::R_OK,
        &config.run_as,
    )? {
        return Err(String::from(
            "pressure-only signing material is readable by the Ota principal",
        ));
    }
    for path in [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/crio/crio.sock",
        "/run/podman/podman.sock",
    ] {
        let path = Path::new(path);
        if path.exists() && target_can_access(path, libc::W_OK, &config.run_as)? {
            return Err(format!(
                "host-control socket is available: {}",
                path.display()
            ));
        }
    }

    let launcher_binary_identity = sha256_identity(
        &fs::read("/usr/lib/ota-authority/bin/ota-authority-launcher")
            .map_err(|error| format!("failed to measure protected launcher binary: {error}"))?,
    );
    let launcher_config_identity = sha256_identity(&config_bytes);
    profile
        .observations
        .iter()
        .map(|required| {
            let semantic_identity = match required.name {
                RuntimeBoundaryObservationName::LauncherBinaryIdentityBound => {
                    Some(launcher_binary_identity.clone())
                }
                RuntimeBoundaryObservationName::LauncherConfigIdentityBound => {
                    Some(launcher_config_identity.clone())
                }
                _ if required.semantic_identity
                    == RuntimeBoundarySemanticIdentityPosture::Required =>
                {
                    return Err(format!(
                        "pressure peer does not implement required identity observation `{:?}`",
                        required.name,
                    ));
                }
                _ => None,
            };
            Ok(RuntimeBoundaryObservation {
                name: required.name,
                state: RuntimeBoundaryObservationState::Verified,
                evidence_method: required.evidence_method,
                reason_code: String::from("verified_by_protected_pressure_launcher"),
                semantic_identity,
            })
        })
        .collect::<Result<Vec<_>, String>>()
}

fn wait_for_single_child_pid(parent_pid: u32, timeout: Duration) -> Result<u32, String> {
    let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    let deadline = Instant::now() + timeout;
    loop {
        let children = fs::read_to_string(&children_path)
            .map_err(|error| format!("failed to inspect protected launcher child: {error}"))?;
        let parsed = children
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| String::from("protected launcher child list is malformed"))?;
        if parsed.len() == 1 {
            return Ok(parsed[0]);
        }
        if parsed.len() > 1 {
            return Err(String::from(
                "protected launcher has more than one Ota child",
            ));
        }
        if Instant::now() >= deadline {
            return Err(String::from("protected launcher child is unavailable"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn verify_process_principal(status: &str, run_as: &PressureRunAs) -> Result<(), String> {
    let uids = parse_proc_status_ids(status, "Uid")?;
    let gids = parse_proc_status_ids(status, "Gid")?;
    let groups = parse_proc_status_ids(status, "Groups")?;
    let no_new_privs = parse_proc_status_decimal(status, "NoNewPrivs")?;
    let capabilities = ["CapInh", "CapPrm", "CapEff", "CapAmb"]
        .map(|name| parse_proc_status_hex(status, name))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if uids.len() != 4
        || !uids.iter().all(|uid| *uid == run_as.uid && *uid != 0)
        || gids.len() != 4
        || !gids.iter().all(|gid| *gid == run_as.gid && *gid != 0)
        || !groups.is_empty()
        || no_new_privs != 1
        || capabilities.iter().any(|capability| *capability != 0)
    {
        return Err(String::from(
            "protected Ota process does not match the constrained launcher principal",
        ));
    }
    Ok(())
}

fn parse_proc_status_ids(status: &str, name: &str) -> Result<Vec<u32>, String> {
    let prefix = format!("{name}:");
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| format!("protected process status omits {name}"))?;
    value
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("protected process status has malformed {name}"))
}

fn parse_proc_status_decimal(status: &str, name: &str) -> Result<u64, String> {
    parse_proc_status_value(status, name).and_then(|value| {
        value
            .parse::<u64>()
            .map_err(|_| format!("protected process status has malformed {name}"))
    })
}

fn parse_proc_status_hex(status: &str, name: &str) -> Result<u64, String> {
    parse_proc_status_value(status, name).and_then(|value| {
        u64::from_str_radix(value, 16)
            .map_err(|_| format!("protected process status has malformed {name}"))
    })
}

fn parse_proc_status_value<'a>(status: &'a str, name: &str) -> Result<&'a str, String> {
    let prefix = format!("{name}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::trim)
        .ok_or_else(|| format!("protected process status omits {name}"))
}

fn verify_unnamed_unix_stream(pid: u32, descriptor: RawFd) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, descriptor);
        Err(String::from(
            "protected runtime-boundary observation requires Linux procfs",
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let session_target = fs::read_link(format!("/proc/{pid}/fd/{descriptor}"))
            .map_err(|error| format!("failed to inspect protected Ota session: {error}"))?;
        let target = session_target.to_string_lossy();
        let inode = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| String::from("protected Ota session is not a socket"))?;
        let unix_sockets = fs::read_to_string("/proc/net/unix")
            .map_err(|error| format!("failed to inspect Unix socket namespace: {error}"))?;
        let matches = unix_sockets
            .lines()
            .skip(1)
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                (fields.len() >= 7 && fields[6] == inode).then_some(fields)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 || matches[0][4] != "0001" || matches[0].len() != 7 {
            return Err(String::from(
                "protected Ota session is not one unnamed Unix stream",
            ));
        }
        Ok(())
    }
}

fn parse_process_environment(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = std::str::from_utf8(entry)
                .map_err(|_| String::from("protected process environment is not UTF-8"))?;
            let (name, value) = entry
                .split_once('=')
                .ok_or_else(|| String::from("protected process environment is malformed"))?;
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn target_can_access(path: &Path, mode: i32, run_as: &PressureRunAs) -> Result<bool, String> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| String::from("protected access-check path contains NUL"))?;
    // SAFETY: the child performs only async-signal-safe identity and access syscalls before
    // exiting. The parent waits synchronously and never executes target-controlled code.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!(
            "failed to fork protected access check: {}",
            std::io::Error::last_os_error()
        ));
    }
    if child == 0 {
        let groups_result = unsafe { libc::setgroups(0, std::ptr::null()) };
        let gid_result = unsafe { libc::setgid(run_as.gid) };
        let uid_result = unsafe { libc::setuid(run_as.uid) };
        if groups_result != 0 || gid_result != 0 || uid_result != 0 {
            unsafe { libc::_exit(2) };
        }
        let access_result = unsafe { libc::access(path.as_ptr(), mode) };
        unsafe { libc::_exit(if access_result == 0 { 0 } else { 1 }) };
    }
    let mut status = 0;
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        return Err(format!(
            "failed to wait for protected access check: {}",
            std::io::Error::last_os_error()
        ));
    }
    if !libc::WIFEXITED(status) {
        return Err(String::from("protected access check did not exit normally"));
    }
    match libc::WEXITSTATUS(status) {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(String::from(
            "protected access check could not assume the launcher principal",
        )),
    }
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
        key_id: String::from(BROKER_KEY_ID),
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

#[cfg(test)]
mod tests {
    use super::*;

    const CONSTRAINED_STATUS: &str = "\
Uid:\t1001\t1001\t1001\t1001\n\
Gid:\t1001\t1001\t1001\t1001\n\
Groups:\t\n\
NoNewPrivs:\t1\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapAmb:\t0000000000000000\n";

    #[test]
    fn pressure_binding_is_explicit_v2_with_disjoint_attestor_authority() {
        let binding = build_pressure_binding().expect("pressure binding");
        assert_eq!(binding["schema_version"], 2);
        assert_eq!(
            binding["attestation"]["protocol_version"],
            RUNTIME_BOUNDARY_ATTESTATION_PROTOCOL_V2
        );
        assert_eq!(
            binding["attestation"]["profile_id"],
            PROTECTED_LAUNCHER_PROFILE_ID_V1
        );
        assert_eq!(
            binding["message_domains"]["attestation_response"],
            ATTESTATION_RESPONSE_DOMAIN_V2
        );
        assert_ne!(
            binding["broker_verifiers"][0]["public_key"],
            binding["attestation"]["verifiers"][0]["public_key"]
        );

        let mut unsigned = binding.clone();
        let identity = unsigned["identity"]
            .as_str()
            .expect("binding identity")
            .to_string();
        unsigned["identity"] = Value::String(String::new());
        assert_eq!(
            message_identity(BROKER_BINDING_IDENTITY_DOMAIN_V2, &unsigned)
                .expect("v2 binding identity"),
            identity
        );
    }

    #[test]
    fn protected_principal_requires_every_identity_slot_and_process_restriction() {
        let run_as = PressureRunAs {
            uid: 1001,
            gid: 1001,
        };
        verify_process_principal(CONSTRAINED_STATUS, &run_as).expect("constrained principal");
        for dishonest in [
            CONSTRAINED_STATUS.replace("Uid:\t1001\t1001\t1001\t1001", "Uid:\t1001\t0\t1001\t1001"),
            CONSTRAINED_STATUS.replace("Groups:\t", "Groups:\t1001"),
            CONSTRAINED_STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            CONSTRAINED_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
        ] {
            assert!(verify_process_principal(&dishonest, &run_as).is_err());
        }
    }

    #[test]
    fn process_environment_requires_exact_launcher_policy() {
        let parsed = parse_process_environment(b"HOME=/home/ota-pressure\0LANG=C.UTF-8\0")
            .expect("process environment");
        assert_eq!(
            parsed.get("HOME"),
            Some(&String::from("/home/ota-pressure"))
        );
        assert_eq!(parsed.get("LANG"), Some(&String::from("C.UTF-8")));
        assert!(parse_process_environment(b"MALFORMED\0").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unnamed_unix_stream_rejects_named_socket() {
        let (stream, _peer) = UnixStream::pair().expect("unnamed pair");
        verify_unnamed_unix_stream(std::process::id(), stream.as_raw_fd())
            .expect("unnamed Unix stream");

        let directory = tempfile::tempdir().expect("socket directory");
        let socket_path = directory.path().join("named.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("named socket");
        assert!(verify_unnamed_unix_stream(std::process::id(), listener.as_raw_fd()).is_err());
    }
}
