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

//! Administrator-only provisioning for the execution-disabled local V3 pressure boundary.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use ota_authority_protocol::{
    ATTESTATION_RESPONSE_DOMAIN_V3, AUTHORIZATION_DECISION_DOMAIN_V1,
    AUTHORIZATION_REQUEST_DOMAIN_V1, BROKER_BINDING_IDENTITY_DOMAIN_V1,
    CHALLENGE_REQUEST_DOMAIN_V1, LEASE_CONSUME_DOMAIN_V1, LEASE_CONSUME_RESPONSE_DOMAIN_V1,
    LEASE_CONSUMPTION_QUERY_DOMAIN_V1, LEASE_CONSUMPTION_STATUS_DOMAIN_V1,
    LEASE_ISSUANCE_DOMAIN_V1, LauncherAttestationProducerBindingV1,
    SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2, SYSTEMD_LAUNCHER_PROFILE_ID_V3,
    SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1, SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3,
    launcher_attestation_producer_binding_v1_identity, message_identity, sha256_identity,
    systemd_job_principal_profile_identity, systemd_job_principal_profile_v2,
    systemd_launcher_profile_identity, systemd_launcher_profile_v3,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::closed_profile_observations::SYSTEMD_ACTIONS;
use crate::config::{
    RunAs, SessionPeer, SystemdAttestationClaimsConfigV1, SystemdJobPrincipalClosedProfileV1,
    SystemdLauncherServiceConfigV1, SystemdPrincipalMappingV1,
    systemd_launcher_service_config_identity,
};
use crate::installation_manifest::{
    ProtectedInstallationFileV1, ProtectedInstallationManifestV1, ProtectedInstallationRoleV1,
    broker_proxy_installation_identity, protected_installation_manifest_identity,
};

const ETC_OTA: &str = "/etc/ota";
const STATE_ROOT: &str = "/var/lib/ota";
const RUNTIME_ROOT: &str = "/run/ota";
const LAUNCHER_CONFIG: &str = "/etc/ota/authority-launcher-systemd.json";
const ATTESTOR_CONFIG: &str = "/etc/ota/authority-attestor.json";
const VERIFIER_SET: &str = "/etc/ota/authority-attestor-verifiers.json";
const INSTALLATION_MANIFEST: &str = "/etc/ota/authority-launcher-installation.json";
const BROKER_STORE: &str = "/etc/ota/crossing-brokers.json";
const SIGNING_KEY: &str = "/var/lib/ota/authority-attestor-signing-key";
const BROKER_SIGNING_KEY: &str = "/var/lib/ota/authority-broker-signing-key";
const BROKER_SCENARIO: &str = "/run/ota/authority-broker-pressure-scenario";
const ISSUANCE_STATE: &str = "/var/lib/ota/authority-attestor";
const LAUNCHER_STATE: &str = "/var/lib/ota/authority-launcher";
const ACTIVE_SLOT_STATE: &str = "/var/lib/ota/authority-launcher/active";
const LAUNCHER_RUNTIME: &str = "/run/ota/authority-launcher";
const LAUNCHER_SOCKET: &str = "/run/ota/authority-launcher.sock";
const ATTESTOR_SOCKET: &str = "/run/ota/authority-attestor.sock";
const BROKER_PROXY_SOCKET: &str = "/run/ota/broker-proxy.sock";
const HOST_CONTROL_SOCKET: &str = "/run/systemd/private";
const LAUNCHER_SERVICE: &str = "/etc/systemd/system/ota-authority-launcher.service";
const LAUNCHER_SERVICE_DROP_IN: &str =
    "/etc/systemd/system/ota-authority-launcher.service.d/zzzz-ota-pressure-hardening.conf";
const LAUNCHER_SOCKET_UNIT: &str = "/etc/systemd/system/ota-authority-launcher.socket";
const ATTESTOR_SERVICE: &str = "/etc/systemd/system/ota-authority-attestor.service";
const ATTESTOR_SERVICE_DROP_IN: &str =
    "/etc/systemd/system/ota-authority-attestor.service.d/zzzz-ota-pressure-hardening.conf";
const ATTESTOR_SOCKET_UNIT: &str = "/etc/systemd/system/ota-authority-attestor.socket";
const BROKER_PROXY_SERVICE: &str = "/etc/systemd/system/ota-authority-broker-proxy.service";
const BROKER_PROXY_SOCKET_UNIT: &str = "/etc/systemd/system/ota-authority-broker-proxy.socket";
const RUNNER_SERVICE: &str = "/etc/systemd/system/ota-authority-pressure-runner.service";
const RUNNER_SERVICE_DROP_IN: &str =
    "/etc/systemd/system/ota-authority-pressure-runner.service.d/zzzz-ota-pressure-hardening.conf";
const ORBSTACK_GLOBAL_SERVICE_DROP_IN: &str = "/run/systemd/system/service.d/zzz-lxc-service.conf";
const INVOCATION_SLICE: &str = "/etc/systemd/system/ota-authority-invocations.slice";
const NON_LOGIN_SHELL: &str = "/usr/sbin/nologin";
const PRESSURE_BROKER_ORIGIN: &str = "https://pressure.invalid";
// Cover the one-second approval window, the 30-second lease ceiling, and scheduling margin.
const ATTESTATION_VALIDITY_SECONDS: u64 = 60;
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PKCHECK: &str = "/usr/bin/pkcheck";
const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/00-ota-authority-deny.rules";
const SUDO: &str = "/usr/bin/sudo";

pub(crate) struct ProvisionRequest {
    pub authority_id: String,
    pub job_user: String,
    pub execution_user: String,
    pub repository_root: PathBuf,
    pub launcher_binary: PathBuf,
    pub attestor_binary: PathBuf,
    pub broker_decision_binary: PathBuf,
    pub ota_binary: PathBuf,
    pub pressure_client_binary: PathBuf,
}

#[derive(Clone)]
struct Account {
    name: String,
    uid: u32,
    gid: u32,
    group: String,
}

pub(crate) fn provision(request: ProvisionRequest) -> Result<u8, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(String::from(
            "root is required for systemd V3 pressure provisioning",
        ));
    }
    crate::validate_authority_label(request.authority_id.as_str())?;
    let job = account(request.job_user.as_str())?;
    let execution = account(request.execution_user.as_str())?;
    if job.uid == 0 || execution.uid == 0 || (job.uid, job.gid) == (execution.uid, execution.gid) {
        return Err(String::from(
            "pressure principals must be distinct non-root accounts",
        ));
    }
    let repository_root = protected_directory(&request.repository_root, Some(execution.uid))?;
    let launcher_binary = protected_executable(&request.launcher_binary)?;
    let attestor_binary = protected_executable(&request.attestor_binary)?;
    let broker_decision_binary = protected_executable(&request.broker_decision_binary)?;
    let ota_binary = protected_executable(&request.ota_binary)?;
    let pressure_client_binary = protected_executable(&request.pressure_client_binary)?;
    for path in [
        Path::new(SYSTEMCTL),
        Path::new(PKCHECK),
        Path::new(NON_LOGIN_SHELL),
    ] {
        protected_executable(path)?;
    }
    if !Path::new(HOST_CONTROL_SOCKET).exists() {
        return Err(String::from(
            "the pressure host-control socket is unavailable",
        ));
    }

    for (path, mode) in protected_directories() {
        create_root_directory(Path::new(path), mode)?;
    }
    create_root_directory(
        Path::new(POLKIT_RULE)
            .parent()
            .ok_or_else(|| String::from("Polkit rule parent unavailable"))?,
        0o755,
    )?;
    for drop_in in [
        LAUNCHER_SERVICE_DROP_IN,
        ATTESTOR_SERVICE_DROP_IN,
        RUNNER_SERVICE_DROP_IN,
    ] {
        create_root_directory(
            Path::new(drop_in)
                .parent()
                .ok_or_else(|| String::from("service drop-in parent unavailable"))?,
            0o755,
        )?;
    }

    let launcher_paths = protected_role_paths(
        &launcher_binary,
        &attestor_binary,
        &broker_decision_binary,
        &ota_binary,
        &pressure_client_binary,
    );
    let read_only_paths = launcher_paths
        .iter()
        .map(|(_, path)| path.to_string_lossy().into_owned())
        .chain([
            String::from(ETC_OTA),
            String::from("/run/systemd/system"),
            String::from(BROKER_PROXY_SOCKET),
            String::from(ATTESTOR_SOCKET),
        ])
        .collect::<Vec<_>>();
    let launcher_service = launcher_service_unit(
        &launcher_binary,
        &repository_root,
        read_only_paths.as_slice(),
    );
    let launcher_socket = launcher_socket_unit(job.group.as_str());
    let attestor_service = attestor_service_unit(&attestor_binary);
    let attestor_socket = attestor_socket_unit();
    let broker_service = broker_proxy_service_unit(&broker_decision_binary);
    let broker_socket = broker_proxy_socket_unit();
    let runner_service = runner_service_unit(
        &request.authority_id,
        &job,
        &repository_root,
        &pressure_client_binary,
    );
    write_root_file(
        Path::new(POLKIT_RULE),
        polkit_deny_rule(&job, &execution)?.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(LAUNCHER_SERVICE),
        launcher_service.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(LAUNCHER_SOCKET_UNIT),
        launcher_socket.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(ATTESTOR_SERVICE),
        attestor_service.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(ATTESTOR_SOCKET_UNIT),
        attestor_socket.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(BROKER_PROXY_SERVICE),
        broker_service.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(BROKER_PROXY_SOCKET_UNIT),
        broker_socket.as_bytes(),
        0o644,
    )?;
    write_root_file(Path::new(RUNNER_SERVICE), runner_service.as_bytes(), 0o644)?;
    write_root_file(
        Path::new(LAUNCHER_SERVICE_DROP_IN),
        launcher_hardening_drop_in(&repository_root, read_only_paths.as_slice()).as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(ATTESTOR_SERVICE_DROP_IN),
        attestor_hardening_drop_in().as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(RUNNER_SERVICE_DROP_IN),
        runner_hardening_drop_in().as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(INVOCATION_SLICE),
        b"[Unit]\nDescription=Ota authority invocation scopes\n",
        0o644,
    )?;

    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| String::from("signing entropy unavailable"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    write_root_file(
        Path::new(SIGNING_KEY),
        URL_SAFE_NO_PAD.encode(seed).as_bytes(),
        0o600,
    )?;
    let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let public_key_identity = sha256_identity(&signing_key.verifying_key().to_bytes());
    let verifier_set = json!({
        "schema_version": 1,
        "verifiers": [{
            "key_id": "systemd-attestor-pressure-v1",
            "algorithm": "ed25519",
            "public_key": public_key,
            "public_key_identity": public_key_identity,
        }]
    });
    write_json(Path::new(VERIFIER_SET), &verifier_set, 0o644)?;

    let launcher_service_identity = sha256_file(Path::new(LAUNCHER_SERVICE))?;
    let launcher_socket_identity = sha256_file(Path::new(LAUNCHER_SOCKET_UNIT))?;
    let broker_service_identity = sha256_file(Path::new(BROKER_PROXY_SERVICE))?;
    let broker_socket_identity = sha256_file(Path::new(BROKER_PROXY_SOCKET_UNIT))?;
    let verifier_set_identity = sha256_file(Path::new(VERIFIER_SET))?;
    let launcher_profile_identity =
        systemd_launcher_profile_identity(&systemd_launcher_profile_v3())
            .map_err(|_| String::from("launcher profile identity unavailable"))?;
    let job_profile_identity =
        systemd_job_principal_profile_identity(&systemd_job_principal_profile_v2())
            .map_err(|_| String::from("job profile identity unavailable"))?;

    let mut launcher_config = SystemdLauncherServiceConfigV1 {
        schema_version: 1,
        identity: String::new(),
        adapter: String::from(SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1),
        socket_path: PathBuf::from(LAUNCHER_SOCKET),
        socket_group_gid: job.gid,
        ota_binary: ota_binary.clone(),
        environment: BTreeMap::from([
            (String::from("HOME"), String::from("/var/empty")),
            (String::from("LANG"), String::from("C.UTF-8")),
            (
                String::from("PATH"),
                String::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            ),
        ]),
        allowed_repository_roots: vec![repository_root.clone()],
        mappings: vec![SystemdPrincipalMappingV1 {
            authority_id: request.authority_id.clone(),
            job_peer: SessionPeer {
                uid: job.uid,
                gid: job.gid,
            },
            execution: RunAs {
                uid: execution.uid,
                gid: execution.gid,
            },
            closed_profile: Some(SystemdJobPrincipalClosedProfileV1 {
                runner_service_unit: String::from("ota-authority-pressure-runner.service"),
                runner_service_fragment_path: PathBuf::from(RUNNER_SERVICE),
                runner_service_drop_in_paths: service_drop_in_paths(RUNNER_SERVICE_DROP_IN),
                non_login_shell: PathBuf::from(NON_LOGIN_SHELL),
                host_control_sockets: vec![PathBuf::from(HOST_CONTROL_SOCKET)],
            }),
        }],
        broker_proxy_socket: PathBuf::from(BROKER_PROXY_SOCKET),
        broker_proxy_peer: SessionPeer { uid: 0, gid: 0 },
        service_unit_identity: launcher_service_identity,
        socket_unit_identity: launcher_socket_identity,
        ota_binary_identity: sha256_file(&ota_binary)?,
        broker_proxy_executable_identity: sha256_file(&broker_decision_binary)?,
        broker_proxy_identity: broker_proxy_installation_identity(
            broker_service_identity.as_str(),
            broker_socket_identity.as_str(),
        )
        .map_err(|_| String::from("broker proxy identity unavailable"))?,
        attestor_key_set_identity: verifier_set_identity.clone(),
        attestation_claims: Some(SystemdAttestationClaimsConfigV1 {
            authenticated_origin: String::from(PRESSURE_BROKER_ORIGIN),
            authority_mounts: vec![String::from("protected-system-authority-store")],
            requested_maximum_validity_seconds: ATTESTATION_VALIDITY_SECONDS,
        }),
        maximum_request_bytes: 64 * 1024,
        maximum_active_sessions: 1,
        maximum_startup_seconds: 30,
        maximum_terminal_wait_seconds: 60,
    };
    launcher_config.identity = systemd_launcher_service_config_identity(&launcher_config)
        .map_err(|_| String::from("launcher configuration identity unavailable"))?;
    write_json(Path::new(LAUNCHER_CONFIG), &launcher_config, 0o600)?;

    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| String::from("pressure clock unavailable"))?;
    let mut producer = LauncherAttestationProducerBindingV1 {
        schema_version: 1,
        identity: String::new(),
        producer_id: String::from("systemd-attestor-pressure"),
        socket_path: String::from(ATTESTOR_SOCKET),
        service_unit: String::from("ota-authority-attestor.service"),
        launcher_service_unit: String::from("ota-authority-launcher.service"),
        launcher_service_binding_identity: launcher_config.service_unit_identity.clone(),
        launcher_configuration_identity: launcher_config.identity.clone(),
        launcher_profile_identity: launcher_profile_identity.clone(),
        launcher_executable_identity: sha256_file(&launcher_binary)?,
        producer_executable_identity: sha256_file(&attestor_binary)?,
        verifier_key_set_identity: verifier_set_identity.clone(),
        signing_key_id: String::from("systemd-attestor-pressure-v1"),
        signing_public_key: public_key.clone(),
        signing_public_key_identity: public_key_identity.clone(),
        signing_key_not_before: format_time(now - time::Duration::hours(1))?,
        signing_key_not_after: format_time(now + time::Duration::days(7))?,
        issuer: String::from("systemd-launcher"),
        audience: String::from("ota-crossing-broker"),
        maximum_attestation_age_seconds: ATTESTATION_VALIDITY_SECONDS,
        verifier_maximum_age_seconds: ATTESTATION_VALIDITY_SECONDS,
        maximum_request_bytes: 64 * 1024,
        read_write_timeout_seconds: 10,
        issuance_state_directory: String::from(ISSUANCE_STATE),
        signing_credential_name: String::from("ota-attestor-ed25519"),
    };
    producer.identity = launcher_attestation_producer_binding_v1_identity(&producer)
        .map_err(|_| String::from("producer binding identity unavailable"))?;
    write_json(
        Path::new(ATTESTOR_CONFIG),
        &json!({ "schema_version": 1, "binding": producer }),
        0o600,
    )?;

    let broker_seed = random_seed()?;
    let broker_key = SigningKey::from_bytes(&broker_seed);
    write_root_file(
        Path::new(BROKER_SIGNING_KEY),
        URL_SAFE_NO_PAD.encode(broker_seed).as_bytes(),
        0o600,
    )?;
    write_root_file(Path::new(BROKER_SCENARIO), b"allowed\n", 0o600)?;
    let mut broker_binding = json!({
        "schema_version": 3,
        "identity": "",
        "authority_id": request.authority_id,
        "broker_id": "execution-disabled-pressure-broker",
        "origin": PRESSURE_BROKER_ORIGIN,
        "server_name": "pressure.invalid",
        "protocol_version": ota_authority_protocol::PROTOCOL_VERSION_V1,
        "transport_authentication": {
            "kind": "mtls",
            "trust_bundle_identity": verifier_set_identity,
            "credential_source_identity": "launcher:execution-disabled-pressure/v1"
        },
        "credential_delivery": {
            "kind": "launcher_session_fd",
            "descriptor": 3,
            "session_audience": "ota-crossing-broker"
        },
        "broker_verifiers": [{
            "key_id": "systemd-broker-pressure-v1",
            "algorithm": "ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(broker_key.verifying_key().to_bytes())
        }],
        "attestation": {
            "protocol_version": SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3,
            "adapter": SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1,
            "systemd_launcher_profile_id": SYSTEMD_LAUNCHER_PROFILE_ID_V3,
            "systemd_launcher_profile_identity": launcher_profile_identity,
            "systemd_job_principal_profile_id": SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2,
            "systemd_job_principal_profile_identity": job_profile_identity,
            "launcher_session_binding_identity": launcher_config.identity,
            "issuer": "systemd-launcher",
            "audience": "ota-crossing-broker",
            "trust_bundle_identity": sha256_identity(signing_key.verifying_key().as_bytes()),
            "verifiers": [{
                "key_id": "systemd-attestor-pressure-v1",
                "algorithm": "ed25519",
                "public_key": public_key
            }],
            "maximum_age_seconds": ATTESTATION_VALIDITY_SECONDS,
            "maximum_clock_skew_seconds": 5,
            "key_rotation_overlap_seconds": 60
        },
        "message_domains": {
            "challenge_request": CHALLENGE_REQUEST_DOMAIN_V1,
            "attestation_response": ATTESTATION_RESPONSE_DOMAIN_V3,
            "authorization_request": AUTHORIZATION_REQUEST_DOMAIN_V1,
            "authorization_decision": AUTHORIZATION_DECISION_DOMAIN_V1,
            "lease_issuance": LEASE_ISSUANCE_DOMAIN_V1,
            "lease_consume": LEASE_CONSUME_DOMAIN_V1,
            "lease_consume_response": LEASE_CONSUME_RESPONSE_DOMAIN_V1,
            "lease_consumption_query": LEASE_CONSUMPTION_QUERY_DOMAIN_V1,
            "lease_consumption_status": LEASE_CONSUMPTION_STATUS_DOMAIN_V1
        },
        "maximum_approval_wait_seconds": 1,
        "minimum_post_approval_freshness_seconds": 5,
        "maximum_lease_seconds": 30
    });
    broker_binding["identity"] = serde_json::Value::String(
        message_identity(BROKER_BINDING_IDENTITY_DOMAIN_V1, &broker_binding)
            .map_err(|_| String::from("broker binding identity unavailable"))?,
    );
    write_json(
        Path::new(BROKER_STORE),
        &json!({ "schema_version": 1, "bindings": [broker_binding] }),
        0o644,
    )?;

    let mut files = protected_role_paths(
        &launcher_binary,
        &attestor_binary,
        &broker_decision_binary,
        &ota_binary,
        &pressure_client_binary,
    )
    .into_iter()
    .map(|(role, path)| {
        Ok(ProtectedInstallationFileV1 {
            role,
            identity: sha256_file(&path)?,
            path,
        })
    })
    .collect::<Result<Vec<_>, String>>()?;
    files.sort_by(|left, right| (left.role, &left.path).cmp(&(right.role, &right.path)));
    let mut manifest = ProtectedInstallationManifestV1 {
        schema_version: 1,
        identity: String::new(),
        launcher_configuration_identity: launcher_config.identity.clone(),
        launcher_profile_identity,
        job_principal_profile_identity: job_profile_identity,
        files,
    };
    manifest.identity = protected_installation_manifest_identity(&manifest)
        .map_err(|_| String::from("installation manifest identity unavailable"))?;
    write_json(Path::new(INSTALLATION_MANIFEST), &manifest, 0o600)?;

    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&[
        "enable",
        "--now",
        "ota-authority-launcher.socket",
        "ota-authority-attestor.socket",
        "ota-authority-broker-proxy.socket",
    ])?;
    println!(
        "systemd-v3-pressure-provisioned authority={} launcher_config={} installation={}",
        launcher_config.identity, LAUNCHER_CONFIG, manifest.identity
    );
    Ok(0)
}

fn protected_role_paths(
    launcher: &Path,
    attestor: &Path,
    broker_decision: &Path,
    ota: &Path,
    pressure_client: &Path,
) -> Vec<(ProtectedInstallationRoleV1, PathBuf)> {
    let mut paths = vec![
        (
            ProtectedInstallationRoleV1::BrokerProxyExecutable,
            broker_decision.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::LauncherExecutable,
            launcher.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::OtaExecutable,
            ota.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::LauncherConfiguration,
            PathBuf::from(LAUNCHER_CONFIG),
        ),
        (
            ProtectedInstallationRoleV1::LauncherServiceUnit,
            PathBuf::from(LAUNCHER_SERVICE),
        ),
        (
            ProtectedInstallationRoleV1::LauncherServiceDropIn,
            PathBuf::from(LAUNCHER_SERVICE_DROP_IN),
        ),
        (
            ProtectedInstallationRoleV1::LauncherSocketUnit,
            PathBuf::from(LAUNCHER_SOCKET_UNIT),
        ),
        (
            ProtectedInstallationRoleV1::BrokerProxyServiceUnit,
            PathBuf::from(BROKER_PROXY_SERVICE),
        ),
        (
            ProtectedInstallationRoleV1::BrokerProxySocketUnit,
            PathBuf::from(BROKER_PROXY_SOCKET_UNIT),
        ),
        (
            ProtectedInstallationRoleV1::AttestorExecutable,
            attestor.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::AttestorConfiguration,
            PathBuf::from(ATTESTOR_CONFIG),
        ),
        (
            ProtectedInstallationRoleV1::AttestorVerifierSet,
            PathBuf::from(VERIFIER_SET),
        ),
        (
            ProtectedInstallationRoleV1::AttestorServiceUnit,
            PathBuf::from(ATTESTOR_SERVICE),
        ),
        (
            ProtectedInstallationRoleV1::AttestorServiceDropIn,
            PathBuf::from(ATTESTOR_SERVICE_DROP_IN),
        ),
        (
            ProtectedInstallationRoleV1::AttestorSocketUnit,
            PathBuf::from(ATTESTOR_SOCKET_UNIT),
        ),
        (
            ProtectedInstallationRoleV1::SystemctlExecutable,
            PathBuf::from(SYSTEMCTL),
        ),
        (
            ProtectedInstallationRoleV1::PkcheckExecutable,
            PathBuf::from(PKCHECK),
        ),
        (
            ProtectedInstallationRoleV1::PolkitRule,
            PathBuf::from(POLKIT_RULE),
        ),
        (
            ProtectedInstallationRoleV1::NonLoginShellExecutable,
            PathBuf::from(NON_LOGIN_SHELL),
        ),
        (
            ProtectedInstallationRoleV1::JobRunnerExecutable,
            pressure_client.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::JobRunnerServiceUnit,
            PathBuf::from(RUNNER_SERVICE),
        ),
        (
            ProtectedInstallationRoleV1::JobRunnerServiceDropIn,
            PathBuf::from(RUNNER_SERVICE_DROP_IN),
        ),
    ];
    if Path::new(ORBSTACK_GLOBAL_SERVICE_DROP_IN).exists() {
        for role in [
            ProtectedInstallationRoleV1::LauncherServiceDropIn,
            ProtectedInstallationRoleV1::AttestorServiceDropIn,
            ProtectedInstallationRoleV1::JobRunnerServiceDropIn,
        ] {
            paths.push((role, PathBuf::from(ORBSTACK_GLOBAL_SERVICE_DROP_IN)));
        }
    }
    if Path::new(SUDO).exists() {
        paths.push((
            ProtectedInstallationRoleV1::SudoExecutable,
            PathBuf::from(SUDO),
        ));
    }
    paths
}

fn polkit_deny_rule(job: &Account, execution: &Account) -> Result<String, String> {
    let users = serde_json::to_string(&[job.name.as_str(), execution.name.as_str()])
        .map_err(|_| String::from("pressure Polkit users could not be encoded"))?;
    let actions = serde_json::to_string(&SYSTEMD_ACTIONS)
        .map_err(|_| String::from("pressure Polkit actions could not be encoded"))?;
    Ok(format!(
        "// Ota pressure-only explicit denial for protected launcher principals.\n\
         polkit.addRule(function(action, subject) {{\n\
           var users = {users};\n\
           var actions = {actions};\n\
           if (users.indexOf(subject.user) !== -1 && actions.indexOf(action.id) !== -1) {{\n\
             return polkit.Result.NO;\n\
           }}\n\
         }});\n"
    ))
}

fn protected_directories() -> [(&'static str, u32); 7] {
    [
        (ETC_OTA, 0o755),
        (STATE_ROOT, 0o755),
        (RUNTIME_ROOT, 0o755),
        (ISSUANCE_STATE, 0o700),
        (LAUNCHER_STATE, 0o700),
        (ACTIVE_SLOT_STATE, 0o700),
        (LAUNCHER_RUNTIME, 0o700),
    ]
}

fn launcher_service_unit(launcher: &Path, repository: &Path, read_only: &[String]) -> String {
    format!(
        "[Unit]\nDescription=Ota protected authority launcher\nRequires=ota-authority-launcher.socket ota-authority-attestor.socket\nAfter=ota-authority-launcher.socket ota-authority-attestor.socket\n\n[Service]\nType=simple\nExecStart={} serve-systemd\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nRestrictSUIDSGID=no\nLockPersonality=yes\nMemoryDenyWriteExecute=no\nRestrictRealtime=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=CAP_KILL CAP_SETGID CAP_SETUID CAP_SYS_PTRACE\nAmbientCapabilities=CAP_SETUID\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nKillMode=control-group\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths={}\nReadWritePaths={} {} {}\n",
        launcher.display(),
        read_only.join(" "),
        LAUNCHER_RUNTIME,
        LAUNCHER_STATE,
        repository.display(),
    )
}

fn launcher_hardening_drop_in(repository: &Path, read_only: &[String]) -> String {
    format!(
        "[Service]\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nRestrictSUIDSGID=no\nLockPersonality=yes\nMemoryDenyWriteExecute=no\nRestrictRealtime=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=CAP_KILL CAP_SETGID CAP_SETUID CAP_SYS_PTRACE\nAmbientCapabilities=CAP_SETUID\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nKillMode=control-group\nInaccessiblePaths=\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths=\nReadOnlyPaths={}\nReadWritePaths=\nReadWritePaths={} {} {}\n",
        read_only.join(" "),
        LAUNCHER_RUNTIME,
        LAUNCHER_STATE,
        repository.display(),
    )
}

fn launcher_socket_unit(group: &str) -> String {
    format!(
        "[Unit]\nDescription=Ota protected authority launcher socket\n\n[Socket]\nListenStream={LAUNCHER_SOCKET}\nSocketUser=root\nSocketGroup={group}\nSocketMode=0660\nAccept=no\nRemoveOnStop=yes\nService=ota-authority-launcher.service\n\n[Install]\nWantedBy=sockets.target\n"
    )
}

fn attestor_service_unit(attestor: &Path) -> String {
    format!(
        "[Unit]\nDescription=Ota protected authority attestor\nRequires=ota-authority-attestor.socket\nAfter=ota-authority-attestor.socket\n\n[Service]\nType=simple\nExecStart={}\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_UNIX\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths={ETC_OTA}\nReadWritePaths={ISSUANCE_STATE}\nLoadCredential=ota-attestor-ed25519:{SIGNING_KEY}\n",
        attestor.display()
    )
}

fn attestor_hardening_drop_in() -> String {
    format!(
        "[Service]\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_UNIX\nInaccessiblePaths=\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths=\nReadOnlyPaths={ETC_OTA} /run/systemd/system\nReadWritePaths=\nReadWritePaths={ISSUANCE_STATE}\nLoadCredential=\nLoadCredential=ota-attestor-ed25519:{SIGNING_KEY}\n"
    )
}

fn attestor_socket_unit() -> String {
    format!(
        "[Unit]\nDescription=Ota protected authority attestor socket\n\n[Socket]\nListenSequentialPacket={ATTESTOR_SOCKET}\nSocketUser=root\nSocketGroup=root\nSocketMode=0600\nAccept=no\nRemoveOnStop=yes\nService=ota-authority-attestor.service\n\n[Install]\nWantedBy=sockets.target\n"
    )
}

fn broker_proxy_service_unit(binary: &Path) -> String {
    format!(
        "[Unit]\nDescription=Execution-disabled Ota signed decision pressure peer\nRequires=ota-authority-broker-proxy.socket\nAfter=ota-authority-broker-proxy.socket\n\n[Service]\nType=simple\nExecStart={}\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateNetwork=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=\nAmbientCapabilities=\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths={BROKER_SCENARIO}\nLoadCredential=ota-broker-ed25519:{BROKER_SIGNING_KEY}\n",
        binary.display()
    )
}

fn broker_proxy_socket_unit() -> String {
    format!(
        "[Unit]\nDescription=Execution-disabled Ota broker proxy socket\n\n[Socket]\nListenStream={BROKER_PROXY_SOCKET}\nSocketUser=root\nSocketGroup=root\nSocketMode=0600\nAccept=no\nRemoveOnStop=yes\nService=ota-authority-broker-proxy.service\n\n[Install]\nWantedBy=sockets.target\n"
    )
}

fn runner_service_unit(
    authority_id: &str,
    account: &Account,
    repository: &Path,
    client: &Path,
) -> String {
    format!(
        "[Unit]\nDescription=Ota V3 protected-launcher pressure client\nAfter=ota-authority-launcher.socket\nRequires=ota-authority-launcher.socket\n\n[Service]\nType=oneshot\nUser={}\nGroup={}\nSupplementaryGroups=\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\nRestrictNamespaces=yes\nRestrictAddressFamilies=AF_UNIX\nWorkingDirectory={}\nExecStart={} --authority-id {} --repository {} --expected-terminal observed-decision-outcome -- run governed --grant {}\n",
        account.name,
        account.group,
        repository.display(),
        client.display(),
        authority_id,
        repository.display(),
        authority_id,
    )
}

fn runner_hardening_drop_in() -> String {
    String::from(
        "[Service]\nSupplementaryGroups=\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\nRestrictNamespaces=yes\nRestrictAddressFamilies=AF_UNIX\n",
    )
}

fn service_drop_in_paths(ota_drop_in: &str) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(ota_drop_in)];
    if Path::new(ORBSTACK_GLOBAL_SERVICE_DROP_IN).exists() {
        paths.push(PathBuf::from(ORBSTACK_GLOBAL_SERVICE_DROP_IN));
    }
    paths.sort();
    paths
}

fn account(name: &str) -> Result<Account, String> {
    let name = CString::new(name).map_err(|_| String::from("invalid account name"))?;
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(String::from("pressure account is unavailable"));
    }
    let record = unsafe { record.assume_init() };
    let group = group_name(record.pw_gid)?;
    Ok(Account {
        name: unsafe { CStr::from_ptr(record.pw_name) }
            .to_str()
            .map_err(|_| String::from("pressure account is malformed"))?
            .to_owned(),
        uid: record.pw_uid,
        gid: record.pw_gid,
        group,
    })
}

fn group_name(gid: u32) -> Result<String, String> {
    let mut record = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getgrgid_r(
            gid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(String::from("pressure group is unavailable"));
    }
    let record = unsafe { record.assume_init() };
    unsafe { CStr::from_ptr(record.gr_name) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| String::from("pressure group is malformed"))
}

fn protected_directory(path: &Path, owner: Option<u32>) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|_| String::from("pressure repository root is unavailable"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| String::from("pressure repository root is unavailable"))?;
    if !metadata.is_dir() || owner.is_some_and(|uid| metadata.uid() != uid) {
        return Err(String::from(
            "pressure repository root ownership is invalid",
        ));
    }
    Ok(path)
}

fn protected_executable(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|_| String::from("protected executable is unavailable"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| String::from("protected executable is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(String::from("protected executable identity is invalid"));
    }
    Ok(path)
}

fn create_root_directory(path: &Path, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|_| String::from("protected directory creation failed"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| String::from("protected directory permissions failed"))
}

fn write_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| String::from("protected JSON serialization failed"))?;
    write_root_file(path, bytes.as_slice(), mode)
}

fn write_root_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_file(&temporary)
            .map_err(|_| String::from("stale temporary file removal failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|_| String::from("protected file creation failed"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| String::from("protected file persistence failed"))?;
    fs::rename(&temporary, path).map_err(|_| String::from("protected file publication failed"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| String::from("protected file permissions failed"))?;
    FileSync::sync_parent(path)
}

struct FileSync;

impl FileSync {
    fn sync_parent(path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| String::from("protected parent unavailable"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| String::from("protected parent synchronization failed"))
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|_| String::from("protected file identity unavailable"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| String::from("pressure entropy unavailable"))?;
    Ok(seed)
}

fn format_time(value: OffsetDateTime) -> Result<String, String> {
    value
        .format(&Rfc3339)
        .map_err(|_| String::from("pressure timestamp unavailable"))
}

fn run_systemctl(arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(SYSTEMCTL)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .status()
        .map_err(|_| String::from("systemd manager unavailable"))?;
    if !status.success() {
        return Err(String::from(
            "systemd manager refused pressure provisioning",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_units_preserve_the_execution_disabled_boundary() {
        let service = launcher_service_unit(
            Path::new("/usr/lib/ota-authority/bin/ota-authority-launcher"),
            Path::new("/srv/ota-pressure"),
            &[String::from("/etc/ota")],
        );
        assert!(service.contains("serve-systemd"));
        assert!(service.contains("RestrictSUIDSGID=no"));
        assert!(service.contains("AmbientCapabilities=CAP_SETUID"));
        assert!(service.contains(&format!(
            "InaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}"
        )));
        assert!(!service.contains("authority-broker execute"));
        let broker = broker_proxy_service_unit(Path::new(
            "/usr/lib/ota-authority/bin/ota-authority-systemd-decision-peer",
        ));
        assert!(broker.contains("CapabilityBoundingSet=\n"));
        assert!(broker.contains("PrivateNetwork=yes"));
        assert!(broker.contains(&format!(
            "InaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}"
        )));
        assert!(attestor_socket_unit().contains("ListenSequentialPacket="));
        assert!(protected_directories().contains(&(ACTIVE_SLOT_STATE, 0o700)));
        let rule = polkit_deny_rule(
            &Account {
                name: String::from("job"),
                uid: 1001,
                gid: 1001,
                group: String::from("job"),
            },
            &Account {
                name: String::from("execution"),
                uid: 1002,
                gid: 1002,
                group: String::from("execution"),
            },
        )
        .expect("bounded Polkit rule");
        assert!(rule.contains("[\"job\",\"execution\"]"));
        assert!(rule.contains("org.freedesktop.systemd1.manage-units"));
        assert!(rule.contains("return polkit.Result.NO"));
        assert!(
            runner_service_unit(
                "release",
                &Account {
                    name: String::from("job"),
                    uid: 1001,
                    gid: 1001,
                    group: String::from("job"),
                },
                Path::new("/srv/ota-pressure"),
                Path::new("/usr/lib/ota-authority/bin/pressure-client"),
            )
            .contains("-- run governed --grant release")
        );
    }

    #[test]
    fn generated_authority_records_share_one_authenticated_origin() {
        let attestation_claims = SystemdAttestationClaimsConfigV1 {
            authenticated_origin: String::from(PRESSURE_BROKER_ORIGIN),
            authority_mounts: vec![String::from("protected-system-authority-store")],
            requested_maximum_validity_seconds: ATTESTATION_VALIDITY_SECONDS,
        };
        let broker_binding = json!({ "origin": PRESSURE_BROKER_ORIGIN });

        assert_eq!(
            broker_binding
                .get("origin")
                .and_then(serde_json::Value::as_str),
            Some(attestation_claims.authenticated_origin.as_str())
        );
    }
}
