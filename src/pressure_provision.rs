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

//! Administrator-only provisioning for the local V3 pressure boundary.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
    LEASE_ISSUANCE_DOMAIN_V1, LauncherAttestationProducerBindingV1, LauncherWorkingDirectoryV1,
    SYSTEMD_JOB_PRINCIPAL_PROFILE_ID_V2, SYSTEMD_LAUNCHER_PROFILE_ID_V3,
    SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1, SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3,
    launcher_attestation_producer_binding_v1_identity, launcher_working_directory_identity,
    message_identity, sha256_identity, systemd_job_principal_profile_identity,
    systemd_job_principal_profile_v2, systemd_launcher_profile_identity,
    systemd_launcher_profile_v3,
};
use serde::{Deserialize, Serialize};
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
    broker_proxy_installation_identity, protected_history_installation_identity,
    protected_installation_manifest_identity,
};
use crate::protected_history::{
    HISTORY_BINDING_PATH, HISTORY_BLOB_ROOT, HISTORY_CATALOG_ROOT, HISTORY_SOCKET_PATH,
    ProtectedHistoryBindingV1, ProtectedHistoryRepositoryMappingV1,
    protected_history_binding_identity, protected_history_repository_mapping_identity,
};

const ETC_OTA: &str = "/etc/ota";
const STATE_ROOT: &str = "/var/lib/ota";
const RUNTIME_ROOT: &str = "/run/ota";
const LAUNCHER_CONFIG: &str = "/etc/ota/authority-launcher-systemd.json";
const ATTESTOR_CONFIG: &str = "/etc/ota/authority-attestor.json";
const VERIFIER_SET: &str = "/etc/ota/authority-attestor-verifiers.json";
const INSTALLATION_MANIFEST: &str = "/etc/ota/authority-launcher-installation.json";
const PUBLIC_INSTALLATION_EVIDENCE_ROOT: &str = "/usr/share/ota/authority-launcher";
const PUBLIC_INSTALLATION_EVIDENCE: &str =
    "/usr/share/ota/authority-launcher/installation-evidence.json";
const RUNNER_PUBLICATION_GATE: &str = PUBLIC_INSTALLATION_EVIDENCE;
const PUBLIC_INSTALLATION_EVIDENCE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.public-installation-evidence.v1\0";
const PREPARED_PROVISIONING_OBSERVATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.prepared-provisioning-observation.v1\0";
const BROKER_STORE: &str = "/etc/ota/crossing-brokers.json";
const SIGNING_KEY: &str = "/var/lib/ota/authority-attestor-signing-key";
const BROKER_SIGNING_KEY: &str = "/var/lib/ota/authority-broker-signing-key";
const BROKER_STATE: &str = "/var/lib/ota/authority-broker-pressure";
const BROKER_SCENARIO: &str = "/var/lib/ota/authority-broker-pressure/scenario";
const ISSUANCE_STATE: &str = "/var/lib/ota/authority-attestor";
const LAUNCHER_STATE: &str = "/var/lib/ota/authority-launcher";
const ACTIVE_SLOT_STATE: &str = "/var/lib/ota/authority-launcher/active";
const FINALIZATION_STATE: &str = "/var/lib/ota/authority-launcher/finalization";
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
const HISTORY_SERVICE: &str = "/etc/systemd/system/ota-authority-history.service";
const HISTORY_SOCKET_UNIT: &str = "/etc/systemd/system/ota-authority-history.socket";
const ORBSTACK_GLOBAL_SERVICE_DROP_IN: &str = "/run/systemd/system/service.d/zzz-lxc-service.conf";
const INVOCATION_SLICE: &str = "/etc/systemd/system/ota-authority-invocations.slice";
const NON_LOGIN_SHELL: &str = "/usr/sbin/nologin";
const PRESSURE_BROKER_ORIGIN: &str = "https://pressure.invalid";
// Cover approval, the lease ceiling, and bounded post-reboot finalization recovery.
const ATTESTATION_VALIDITY_SECONDS: u64 = 180;
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PKCHECK: &str = "/usr/bin/pkcheck";
const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/00-ota-authority-deny.rules";
const SUDO: &str = "/usr/bin/sudo";
const HISTORY_OPERATOR_PROFILE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-operator-profile.v1\0";
const HISTORY_REPOSITORY_BINDING_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-repository-binding.v1\0";
const HISTORY_CATALOG_NAMESPACE_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-catalog-namespace.v1\0";

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
    pub prepared_runner_binary: Option<PathBuf>,
    pub production_client: bool,
}

#[derive(Clone, Serialize)]
struct PublicInstallationEvidenceV1 {
    schema_version: u32,
    identity: String,
    protocol_source_revision: String,
    core_source_revision: String,
    launcher_source_revision: String,
    prepared_provisioning_observation: Option<PreparedProvisioningObservationV1>,
    installation_manifest: ProtectedInstallationManifestV1,
}

#[derive(Clone, Serialize)]
struct PreparedProvisioningObservationV1 {
    schema_version: u32,
    identity: String,
    observed_at: String,
    runner_service_unit: String,
    runner_active_state: String,
    runner_sub_state: String,
    runner_main_pid: u32,
    runner_control_group: String,
    runner_service_fragment_path: String,
    runner_service_drop_in_paths: Vec<String>,
    runner_executable_identity: String,
    runner_service_identity: String,
    runner_drop_in_identity: String,
    job_uid: u32,
    execution_uid: u32,
    live_principal_processes: Vec<u32>,
    authority_state_posture: String,
    authority_state_ancestor_posture: String,
    authority_state_paths_checked: Vec<String>,
    authority_unit_posture: String,
    authority_units_checked: Vec<String>,
    authority_socket_listener_posture: String,
    authority_socket_paths_checked: Vec<String>,
}

#[derive(Deserialize)]
struct OtaBuildIdentity {
    source_build: bool,
    commit: Option<String>,
    dirty: bool,
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
    if job.uid == 0 || execution.uid == 0 || job.uid == execution.uid || job.gid == execution.gid {
        return Err(String::from(
            "pressure principals must be distinct non-root accounts",
        ));
    }
    let repository_root = protected_repository_tree(&request.repository_root, &job, &execution)?;
    let launcher_binary = protected_executable(&request.launcher_binary)?;
    if sha256_file(Path::new("/proc/self/exe"))? != sha256_file(&launcher_binary)? {
        return Err(String::from(
            "provisioning process does not match the installed Launcher binary",
        ));
    }
    let attestor_binary = protected_executable(&request.attestor_binary)?;
    let broker_decision_binary = protected_executable(&request.broker_decision_binary)?;
    let ota_binary = protected_executable(&request.ota_binary)?;
    let pressure_client_binary = protected_executable(&request.pressure_client_binary)?;
    let prepared_runner_binary = request
        .prepared_runner_binary
        .as_deref()
        .map(|path| {
            verify_root_protected_chain(path)?;
            let protected = protected_executable(path)?;
            if protected != path {
                return Err(String::from(
                    "prepared runner executable must not use an alias",
                ));
            }
            Ok(protected)
        })
        .transpose()?;
    let job_runner_binary = prepared_runner_binary
        .as_deref()
        .unwrap_or(pressure_client_binary.as_path())
        .to_path_buf();
    let source_revisions = build_source_revisions(&ota_binary)?;
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

    let prepared_provisioning_observation = prepared_runner_binary
        .as_deref()
        .map(|runner| observe_prepared_provisioning_precondition(&job, &execution, runner))
        .transpose()?;

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
        &job_runner_binary,
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
    let runner_service = prepared_runner_binary.is_none().then(|| {
        runner_service_unit(
            &request.authority_id,
            &job,
            &repository_root,
            &pressure_client_binary,
            request.production_client,
        )
    });
    let history_service = history_service_unit(&launcher_binary);
    let history_socket = history_socket_unit(job.group.as_str());
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
    if let Some(runner_service) = runner_service.as_deref() {
        write_root_file(Path::new(RUNNER_SERVICE), runner_service.as_bytes(), 0o644)?;
    } else {
        protected_root_file(Path::new(RUNNER_SERVICE), false)?;
        verify_root_protected_chain(Path::new(RUNNER_SERVICE))?;
    }
    write_root_file(
        Path::new(HISTORY_SERVICE),
        history_service.as_bytes(),
        0o644,
    )?;
    write_root_file(
        Path::new(HISTORY_SOCKET_UNIT),
        history_socket.as_bytes(),
        0o644,
    )?;
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
    if prepared_runner_binary.is_none() {
        write_root_file(
            Path::new(RUNNER_SERVICE_DROP_IN),
            runner_hardening_drop_in().as_bytes(),
            0o644,
        )?;
    } else {
        protected_root_file(Path::new(RUNNER_SERVICE_DROP_IN), false)?;
        verify_root_protected_chain(Path::new(RUNNER_SERVICE_DROP_IN))?;
    }
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
        &job_runner_binary,
    )
    .into_iter()
    .map(|(role, path)| {
        Ok(ProtectedInstallationFileV1 {
            role,
            identity: if role == ProtectedInstallationRoleV1::HistoryBinding {
                format!("sha256:{}", "0".repeat(64))
            } else {
                sha256_file(&path)?
            },
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
    let repository_metadata = fs::metadata(&repository_root)
        .map_err(|_| String::from("pressure repository metadata unavailable"))?;
    let mut working_directory = LauncherWorkingDirectoryV1 {
        schema_version: 1,
        identity: String::new(),
        logical_path: repository_root.to_string_lossy().into_owned(),
        device: repository_metadata.dev(),
        inode: repository_metadata.ino(),
    };
    working_directory.identity = launcher_working_directory_identity(&working_directory)
        .map_err(|_| String::from("history working-directory identity unavailable"))?;
    let repository_binding_identity = message_identity(
        HISTORY_REPOSITORY_BINDING_IDENTITY_DOMAIN_V1,
        &(
            launcher_config.identity.as_str(),
            request.authority_id.as_str(),
            working_directory.identity.as_str(),
        ),
    )
    .map_err(|_| String::from("history repository binding identity unavailable"))?;
    let catalog_namespace_identity = message_identity(
        HISTORY_CATALOG_NAMESPACE_IDENTITY_DOMAIN_V1,
        &(
            repository_binding_identity.as_str(),
            request.authority_id.as_str(),
        ),
    )
    .map_err(|_| String::from("history catalog namespace identity unavailable"))?;
    create_root_directory(
        &catalog_namespace_directory(&catalog_namespace_identity)?,
        0o700,
    )?;
    let mut history_mapping = ProtectedHistoryRepositoryMappingV1 {
        schema_version: 1,
        identity: String::new(),
        repository_binding_identity,
        catalog_namespace_identity,
        authority_id: request.authority_id.clone(),
        working_directory,
    };
    history_mapping.identity = protected_history_repository_mapping_identity(&history_mapping)
        .map_err(|_| String::from("history repository mapping identity unavailable"))?;
    let history_installation_identity = protected_history_installation_identity(&manifest)
        .map_err(|_| String::from("history installation identity unavailable"))?;
    let ota_identity = sha256_file(&ota_binary)?;
    let operator_profile_identity = message_identity(
        HISTORY_OPERATOR_PROFILE_IDENTITY_DOMAIN_V1,
        &(
            job.uid,
            job.gid,
            ota_identity.as_str(),
            "primary_group_only:no_new_privs:no_process_capabilities",
        ),
    )
    .map_err(|_| String::from("history operator profile identity unavailable"))?;
    let mut history_binding = ProtectedHistoryBindingV1 {
        schema_version: 1,
        identity: String::new(),
        protocol_profile: ota_authority_protocol::SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        socket_path: PathBuf::from(HISTORY_SOCKET_PATH),
        socket_group_gid: job.gid,
        installation_manifest_identity: history_installation_identity,
        installed_client_path: ota_binary.clone(),
        installed_client_identity: ota_identity,
        operator_uid: job.uid,
        operator_gid: job.gid,
        operator_profile_identity,
        service_unit_identity: sha256_file(Path::new(HISTORY_SERVICE))?,
        socket_unit_identity: sha256_file(Path::new(HISTORY_SOCKET_UNIT))?,
        blob_root: PathBuf::from(HISTORY_BLOB_ROOT),
        catalog_root: PathBuf::from(HISTORY_CATALOG_ROOT),
        maximum_response_bytes: ota_authority_protocol::MAX_HISTORY_RESPONSE_BYTES_V1,
        maximum_entry_count: ota_authority_protocol::MAX_HISTORY_ENTRY_COUNT_V1 as u32,
        mappings: vec![history_mapping],
    };
    history_binding.identity = protected_history_binding_identity(&history_binding)
        .map_err(|_| String::from("history binding identity unavailable"))?;
    write_json(Path::new(HISTORY_BINDING_PATH), &history_binding, 0o600)?;
    manifest
        .files
        .iter_mut()
        .find(|entry| entry.role == ProtectedInstallationRoleV1::HistoryBinding)
        .ok_or_else(|| String::from("history binding manifest entry unavailable"))?
        .identity = sha256_file(Path::new(HISTORY_BINDING_PATH))?;
    manifest.identity = protected_installation_manifest_identity(&manifest)
        .map_err(|_| String::from("installation manifest identity unavailable"))?;
    write_json(Path::new(INSTALLATION_MANIFEST), &manifest, 0o600)?;
    create_root_directory(Path::new(PUBLIC_INSTALLATION_EVIDENCE_ROOT), 0o755)?;
    verify_root_protected_chain(Path::new(PUBLIC_INSTALLATION_EVIDENCE_ROOT))?;
    let mut public_evidence = PublicInstallationEvidenceV1 {
        schema_version: 1,
        identity: String::new(),
        protocol_source_revision: source_revisions.0,
        core_source_revision: source_revisions.1,
        launcher_source_revision: source_revisions.2,
        prepared_provisioning_observation,
        installation_manifest: manifest,
    };
    public_evidence.identity = public_installation_evidence_identity(&public_evidence)?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&[
        "enable",
        "ota-authority-launcher.socket",
        "ota-authority-attestor.socket",
        "ota-authority-broker-proxy.socket",
        "ota-authority-history.socket",
    ])?;
    run_systemctl(&[
        "start",
        "ota-authority-launcher.socket",
        "ota-authority-attestor.socket",
        "ota-authority-broker-proxy.socket",
        "ota-authority-history.socket",
    ])?;
    verify_exact_socket_unit_owner(LAUNCHER_SOCKET, "ota-authority-launcher.socket")?;
    verify_exact_socket_unit_owner(ATTESTOR_SOCKET, "ota-authority-attestor.socket")?;
    verify_exact_socket_unit_owner(BROKER_PROXY_SOCKET, "ota-authority-broker-proxy.socket")?;
    verify_exact_socket_unit_owner(HISTORY_SOCKET_PATH, "ota-authority-history.socket")?;
    verify_activated_socket(Path::new(LAUNCHER_SOCKET), job.gid, 0o660)?;
    verify_activated_socket(Path::new(HISTORY_SOCKET_PATH), job.gid, 0o660)?;
    verify_activated_socket(Path::new(ATTESTOR_SOCKET), 0, 0o600)?;
    verify_activated_socket(Path::new(BROKER_PROXY_SOCKET), 0, 0o600)?;
    // The canonical runner cannot start until this final, durable publication succeeds.
    write_json(
        Path::new(PUBLIC_INSTALLATION_EVIDENCE),
        &public_evidence,
        0o644,
    )?;
    protected_root_file(Path::new(PUBLIC_INSTALLATION_EVIDENCE), false)?;
    verify_root_protected_chain(Path::new(PUBLIC_INSTALLATION_EVIDENCE))?;
    println!(
        "systemd-v3-pressure-provisioned authority={} launcher_config={} installation={}",
        launcher_config.identity, LAUNCHER_CONFIG, public_evidence.installation_manifest.identity
    );
    Ok(0)
}

fn protected_role_paths(
    launcher: &Path,
    attestor: &Path,
    broker_decision: &Path,
    ota: &Path,
    pressure_client: &Path,
    job_runner: &Path,
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
            job_runner.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::ProductionClientExecutable,
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
        (
            ProtectedInstallationRoleV1::HistoryClientExecutable,
            ota.to_path_buf(),
        ),
        (
            ProtectedInstallationRoleV1::HistoryBinding,
            PathBuf::from(HISTORY_BINDING_PATH),
        ),
        (
            ProtectedInstallationRoleV1::HistoryServiceUnit,
            PathBuf::from(HISTORY_SERVICE),
        ),
        (
            ProtectedInstallationRoleV1::HistorySocketUnit,
            PathBuf::from(HISTORY_SOCKET_UNIT),
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

fn protected_directories() -> [(&'static str, u32); 11] {
    [
        (ETC_OTA, 0o755),
        (STATE_ROOT, 0o755),
        (RUNTIME_ROOT, 0o755),
        (ISSUANCE_STATE, 0o700),
        (LAUNCHER_STATE, 0o700),
        (ACTIVE_SLOT_STATE, 0o700),
        (FINALIZATION_STATE, 0o700),
        (BROKER_STATE, 0o700),
        (LAUNCHER_RUNTIME, 0o700),
        (HISTORY_BLOB_ROOT, 0o700),
        (HISTORY_CATALOG_ROOT, 0o700),
    ]
}

fn launcher_service_unit(launcher: &Path, repository: &Path, read_only: &[String]) -> String {
    format!(
        "[Unit]\nDescription=Ota protected authority launcher\nRequires=ota-authority-launcher.socket ota-authority-attestor.socket\nAfter=ota-authority-launcher.socket ota-authority-attestor.socket\n\n[Service]\nType=simple\nExecStart={} serve-systemd\nUser=root\nGroup=root\nUMask=0077\nRuntimeDirectory=ota/authority-launcher\nRuntimeDirectoryMode=0700\nNoNewPrivileges=yes\nRestrictSUIDSGID=no\nLockPersonality=yes\nMemoryDenyWriteExecute=no\nRestrictRealtime=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_KILL CAP_SETGID CAP_SETUID CAP_SYS_PTRACE\nAmbientCapabilities=CAP_SETUID\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nKillMode=control-group\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths={}\nReadWritePaths={} {} {} {HISTORY_BLOB_ROOT} {HISTORY_CATALOG_ROOT}\n",
        launcher.display(),
        read_only.join(" "),
        LAUNCHER_RUNTIME,
        LAUNCHER_STATE,
        repository.display(),
    )
}

fn launcher_hardening_drop_in(repository: &Path, read_only: &[String]) -> String {
    format!(
        "[Service]\nUser=root\nGroup=root\nUMask=0077\nRuntimeDirectory=ota/authority-launcher\nRuntimeDirectoryMode=0700\nNoNewPrivileges=yes\nRestrictSUIDSGID=no\nLockPersonality=yes\nMemoryDenyWriteExecute=no\nRestrictRealtime=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_KILL CAP_SETGID CAP_SETUID CAP_SYS_PTRACE\nAmbientCapabilities=CAP_SETUID\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nKillMode=control-group\nInaccessiblePaths=\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths=\nReadOnlyPaths={}\nReadWritePaths=\nReadWritePaths={} {} {} {HISTORY_BLOB_ROOT} {HISTORY_CATALOG_ROOT}\n",
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

fn history_service_unit(launcher: &Path) -> String {
    format!(
        "[Unit]\nDescription=Ota protected receipt history\nRequires=ota-authority-history.socket\nAfter=ota-authority-history.socket\n\n[Service]\nType=simple\nExecStart={} serve-history\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX\nReadOnlyPaths={ETC_OTA} {HISTORY_BLOB_ROOT} {HISTORY_CATALOG_ROOT}\n",
        launcher.display()
    )
}

fn history_socket_unit(group: &str) -> String {
    format!(
        "[Unit]\nDescription=Ota protected receipt history socket\n\n[Socket]\nListenStream={HISTORY_SOCKET_PATH}\nSocketUser=root\nSocketGroup={group}\nSocketMode=0660\nAccept=no\nRemoveOnStop=yes\nService=ota-authority-history.service\n\n[Install]\nWantedBy=sockets.target\n"
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
        "[Unit]\nDescription=Execution-disabled Ota signed decision pressure peer\nRequires=ota-authority-broker-proxy.socket\nAfter=ota-authority-broker-proxy.socket\n\n[Service]\nType=simple\nExecStart={}\nUser=root\nGroup=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nPrivateNetwork=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nCapabilityBoundingSet=\nAmbientCapabilities=\nSupplementaryGroups=\nRestrictAddressFamilies=AF_UNIX\nInaccessiblePaths={SIGNING_KEY} {BROKER_SIGNING_KEY}\nReadOnlyPaths={BROKER_SCENARIO}\nReadWritePaths={BROKER_STATE}\nLoadCredential=ota-broker-ed25519:{BROKER_SIGNING_KEY}\n",
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
    production_client: bool,
) -> String {
    let client_arguments = if production_client {
        format!(
            "--authority-id {authority_id} --repository {} --json -- run governed --grant {authority_id} --receipt",
            repository.display()
        )
    } else {
        format!(
            "--authority-id {authority_id} --repository {} --expected-terminal observed-decision-outcome -- run governed --grant {authority_id} --receipt",
            repository.display()
        )
    };
    format!(
        "[Unit]\nDescription=Ota V3 protected-launcher pressure client\nAfter=ota-authority-launcher.socket\nRequires=ota-authority-launcher.socket\nConditionPathExists={RUNNER_PUBLICATION_GATE}\n\n[Service]\nType=oneshot\nUser={}\nGroup={}\nSupplementaryGroups=\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\nRestrictNamespaces=yes\nRestrictAddressFamilies=AF_UNIX\nSyslogIdentifier=ota-authority-pressure-client\nWorkingDirectory={}\nExecStart={} {}\n",
        account.name,
        account.group,
        repository.display(),
        client.display(),
        client_arguments,
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

fn catalog_namespace_directory(identity: &str) -> Result<PathBuf, String> {
    let name = identity
        .strip_prefix("sha256:")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| String::from("history catalog namespace identity unavailable"))?;
    Ok(Path::new(HISTORY_CATALOG_ROOT).join(name))
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

fn validate_git_revision(value: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(String::from(
            "pressure source revisions must be exact lowercase Git commit identities",
        ))
    }
}

fn build_source_revisions(ota_binary: &Path) -> Result<(String, String, String), String> {
    let protocol = option_env!("OTA_PROTOCOL_BUILD_REVISION")
        .ok_or_else(|| String::from("Protocol build revision is unavailable"))?
        .to_owned();
    let launcher = option_env!("OTA_LAUNCHER_BUILD_COMMIT")
        .ok_or_else(|| String::from("Launcher build revision is unavailable"))?
        .to_owned();
    if option_env!("OTA_LAUNCHER_BUILD_DIRTY").is_some() {
        return Err(String::from("Launcher source build is dirty"));
    }
    validate_git_revision(&protocol)?;
    validate_git_revision(&launcher)?;

    let output = Command::new(ota_binary)
        .args(["--version", "--json"])
        .output()
        .map_err(|_| String::from("installed Ota build identity is unavailable"))?;
    if !output.status.success() {
        return Err(String::from("installed Ota build identity refused"));
    }
    let identity: OtaBuildIdentity = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from("installed Ota build identity is malformed"))?;
    let core = identity
        .commit
        .filter(|_| identity.source_build && !identity.dirty)
        .ok_or_else(|| String::from("installed Ota must be a clean source build"))?;
    validate_git_revision(&core)?;
    Ok((protocol, core, launcher))
}

fn observe_prepared_provisioning_precondition(
    job: &Account,
    execution: &Account,
    runner_binary: &Path,
) -> Result<PreparedProvisioningObservationV1, String> {
    protected_root_file(Path::new(RUNNER_SERVICE), false)?;
    verify_root_protected_chain(Path::new(RUNNER_SERVICE))?;
    protected_root_file(Path::new(RUNNER_SERVICE_DROP_IN), false)?;
    verify_root_protected_chain(Path::new(RUNNER_SERVICE_DROP_IN))?;
    let expected_drop_ins = service_drop_in_paths(RUNNER_SERVICE_DROP_IN);
    verify_runner_publication_gate(Path::new(RUNNER_SERVICE), expected_drop_ins.as_slice())?;

    let properties = systemctl_properties(
        "ota-authority-pressure-runner.service",
        &[
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "ControlGroup",
            "FragmentPath",
            "DropInPaths",
        ],
    )?;
    let load_state = properties
        .get("LoadState")
        .ok_or_else(|| String::from("prepared runner load state is unavailable"))?;
    let active_state = properties
        .get("ActiveState")
        .ok_or_else(|| String::from("prepared runner active state is unavailable"))?;
    let sub_state = properties
        .get("SubState")
        .ok_or_else(|| String::from("prepared runner substate is unavailable"))?;
    let main_pid = properties
        .get("MainPID")
        .ok_or_else(|| String::from("prepared runner main PID is unavailable"))?
        .parse::<u32>()
        .map_err(|_| String::from("prepared runner main PID is malformed"))?;
    let control_group = properties
        .get("ControlGroup")
        .ok_or_else(|| String::from("prepared runner control group is unavailable"))?;
    let fragment_path = properties
        .get("FragmentPath")
        .ok_or_else(|| String::from("prepared runner fragment path is unavailable"))?;
    let mut loaded_drop_ins = properties
        .get("DropInPaths")
        .ok_or_else(|| String::from("prepared runner drop-in paths are unavailable"))?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    loaded_drop_ins.sort();
    let mut expected_drop_in_paths = expected_drop_ins
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    expected_drop_in_paths.sort();
    if fragment_path != RUNNER_SERVICE || loaded_drop_ins != expected_drop_in_paths {
        return Err(String::from(
            "prepared runner service must use the exact fragment and drop-in set",
        ));
    }
    if load_state != "loaded"
        || active_state != "inactive"
        || sub_state != "dead"
        || main_pid != 0
        || !control_group.is_empty()
    {
        return Err(String::from(
            "prepared runner service must be loaded, inactive, dead, and process-free",
        ));
    }

    let live_principal_processes = live_processes_for_uids(&[job.uid, execution.uid])?;
    if !live_principal_processes.is_empty() {
        return Err(String::from(
            "prepared provisioning requires no live job or execution-principal process",
        ));
    }
    let authority_state_paths_checked = managed_authority_state_paths()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let authority_units_checked = require_managed_authority_units_inactive()?;
    let authority_socket_paths_checked = require_managed_socket_paths_unowned()?;
    verify_managed_authority_ancestor_chains(authority_state_paths_checked.as_slice())?;
    require_managed_authority_state_absent(authority_state_paths_checked.as_slice())?;

    let observed_at = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| String::from("prepared provisioning observation clock unavailable"))?
        .format(&Rfc3339)
        .map_err(|_| String::from("prepared provisioning observation time unavailable"))?;
    let mut observation = PreparedProvisioningObservationV1 {
        schema_version: 1,
        identity: String::new(),
        observed_at,
        runner_service_unit: String::from("ota-authority-pressure-runner.service"),
        runner_active_state: active_state.clone(),
        runner_sub_state: sub_state.clone(),
        runner_main_pid: main_pid,
        runner_control_group: control_group.clone(),
        runner_service_fragment_path: fragment_path.clone(),
        runner_service_drop_in_paths: loaded_drop_ins,
        runner_executable_identity: sha256_file(runner_binary)?,
        runner_service_identity: sha256_file(Path::new(RUNNER_SERVICE))?,
        runner_drop_in_identity: sha256_file(Path::new(RUNNER_SERVICE_DROP_IN))?,
        job_uid: job.uid,
        execution_uid: execution.uid,
        live_principal_processes,
        authority_state_posture: String::from("fresh_managed_authority_state"),
        authority_state_ancestor_posture: String::from(
            "root_owned_non_writable_directory_chain_without_aliases",
        ),
        authority_state_paths_checked,
        authority_unit_posture: String::from("inactive_or_not_found_before_mutation"),
        authority_units_checked,
        authority_socket_listener_posture: String::from(
            "no_loaded_systemd_socket_unit_owns_managed_path_before_mutation",
        ),
        authority_socket_paths_checked,
    };
    observation.identity = prepared_provisioning_observation_identity(&observation)?;
    Ok(observation)
}

fn verify_runner_publication_gate(service: &Path, drop_ins: &[PathBuf]) -> Result<(), String> {
    let expected = format!("ConditionPathExists={RUNNER_PUBLICATION_GATE}");
    let mut conditions = Vec::new();
    for path in std::iter::once(service).chain(drop_ins.iter().map(PathBuf::as_path)) {
        let content = fs::read_to_string(path)
            .map_err(|_| String::from("prepared runner unit configuration is unreadable"))?;
        conditions.extend(
            content
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("ConditionPathExists="))
                .map(str::to_owned),
        );
    }
    if conditions != [expected] {
        return Err(String::from(
            "prepared runner service must use the exact installation-evidence publication gate",
        ));
    }
    Ok(())
}

fn prepared_provisioning_observation_identity(
    observation: &PreparedProvisioningObservationV1,
) -> Result<String, String> {
    let mut canonical = observation.clone();
    canonical.identity.clear();
    message_identity(
        PREPARED_PROVISIONING_OBSERVATION_IDENTITY_DOMAIN_V1,
        &canonical,
    )
    .map_err(|_| String::from("prepared provisioning observation identity unavailable"))
}

fn systemctl_properties(unit: &str, names: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let mut command = Command::new(SYSTEMCTL);
    command.arg("show").arg(unit).arg("--no-pager");
    for name in names {
        command.arg(format!("--property={name}"));
    }
    let output = command
        .output()
        .map_err(|_| String::from("prepared runner service observation unavailable"))?;
    if !output.status.success() {
        return Err(String::from("prepared runner service observation refused"));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| String::from("prepared runner service observation malformed"))?
        .lines()
        .map(|line| {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| String::from("prepared runner service property malformed"))?;
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn live_processes_for_uids(uids: &[u32]) -> Result<Vec<u32>, String> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")
        .map_err(|_| String::from("process inventory unavailable before provisioning"))?
    {
        let entry = entry.map_err(|_| String::from("process inventory changed unexpectedly"))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(String::from(
                    "process identity unavailable before provisioning",
                ));
            }
        };
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| String::from("process identity malformed before provisioning"))?;
        if uids.contains(&uid) {
            processes.push(pid);
        }
    }
    processes.sort_unstable();
    Ok(processes)
}

fn managed_authority_state_paths() -> Vec<&'static str> {
    vec![
        LAUNCHER_CONFIG,
        ATTESTOR_CONFIG,
        VERIFIER_SET,
        INSTALLATION_MANIFEST,
        PUBLIC_INSTALLATION_EVIDENCE_ROOT,
        BROKER_STORE,
        SIGNING_KEY,
        BROKER_SIGNING_KEY,
        BROKER_STATE,
        BROKER_SCENARIO,
        ISSUANCE_STATE,
        LAUNCHER_STATE,
        LAUNCHER_RUNTIME,
        LAUNCHER_SOCKET,
        ATTESTOR_SOCKET,
        BROKER_PROXY_SOCKET,
        HISTORY_SOCKET_PATH,
        LAUNCHER_SERVICE,
        LAUNCHER_SERVICE_DROP_IN,
        LAUNCHER_SOCKET_UNIT,
        ATTESTOR_SERVICE,
        ATTESTOR_SERVICE_DROP_IN,
        ATTESTOR_SOCKET_UNIT,
        BROKER_PROXY_SERVICE,
        BROKER_PROXY_SOCKET_UNIT,
        HISTORY_BINDING_PATH,
        HISTORY_BLOB_ROOT,
        HISTORY_CATALOG_ROOT,
        HISTORY_SERVICE,
        HISTORY_SOCKET_UNIT,
        INVOCATION_SLICE,
        POLKIT_RULE,
    ]
}

fn managed_authority_units() -> [&'static str; 8] {
    [
        "ota-authority-launcher.service",
        "ota-authority-launcher.socket",
        "ota-authority-attestor.service",
        "ota-authority-attestor.socket",
        "ota-authority-broker-proxy.service",
        "ota-authority-broker-proxy.socket",
        "ota-authority-history.service",
        "ota-authority-history.socket",
    ]
}

fn managed_authority_socket_paths() -> [&'static str; 4] {
    [
        LAUNCHER_SOCKET,
        ATTESTOR_SOCKET,
        BROKER_PROXY_SOCKET,
        HISTORY_SOCKET_PATH,
    ]
}

fn systemd_socket_units() -> Result<BTreeMap<String, Vec<String>>, String> {
    let output = Command::new(SYSTEMCTL)
        .args([
            "list-sockets",
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|_| String::from("systemd socket inventory is unavailable"))?;
    if !output.status.success() {
        return Err(String::from("systemd socket inventory was refused"));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| String::from("systemd socket inventory is malformed"))?;
    Ok(parse_systemd_socket_units(stdout.as_str()))
}

fn parse_systemd_socket_units(output: &str) -> BTreeMap<String, Vec<String>> {
    let mut sockets = BTreeMap::<String, Vec<String>>::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(path) = fields.next() else {
            continue;
        };
        let Some(unit) = fields.next() else {
            continue;
        };
        sockets
            .entry(path.to_owned())
            .or_default()
            .push(unit.to_owned());
    }
    for units in sockets.values_mut() {
        units.sort();
        units.dedup();
    }
    sockets
}

fn require_managed_socket_paths_unowned() -> Result<Vec<String>, String> {
    let sockets = systemd_socket_units()?;
    let checked = managed_authority_socket_paths()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if checked.iter().any(|path| sockets.contains_key(path)) {
        return Err(String::from(
            "prepared provisioning requires every managed socket path to have no loaded systemd owner",
        ));
    }
    Ok(checked)
}

fn verify_exact_socket_unit_owner(path: &str, expected_unit: &str) -> Result<(), String> {
    let sockets = systemd_socket_units()?;
    if sockets.get(path).map(Vec::as_slice) != Some(&[expected_unit.to_owned()]) {
        return Err(String::from(
            "activated authority socket does not have exactly one canonical systemd owner",
        ));
    }
    Ok(())
}

fn require_managed_authority_units_inactive() -> Result<Vec<String>, String> {
    let mut checked = Vec::new();
    for unit in managed_authority_units() {
        let property_names = if unit.ends_with(".service") {
            &["LoadState", "ActiveState", "SubState", "MainPID"][..]
        } else {
            &["LoadState", "ActiveState", "SubState"][..]
        };
        let properties = systemctl_properties(unit, property_names)?;
        let load_state = properties
            .get("LoadState")
            .ok_or_else(|| String::from("managed authority unit load state is unavailable"))?;
        let active_state = properties
            .get("ActiveState")
            .ok_or_else(|| String::from("managed authority unit active state is unavailable"))?;
        let sub_state = properties
            .get("SubState")
            .ok_or_else(|| String::from("managed authority unit substate is unavailable"))?;
        if !matches!(load_state.as_str(), "loaded" | "not-found")
            || active_state != "inactive"
            || sub_state != "dead"
            || (unit.ends_with(".service")
                && properties.get("MainPID").map(String::as_str) != Some("0"))
        {
            return Err(String::from(
                "prepared provisioning requires every managed authority unit to be inactive",
            ));
        }
        checked.push(unit.to_owned());
    }
    Ok(checked)
}

fn verify_activated_socket(
    path: &Path,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| String::from("activated authority socket is unavailable"))?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != expected_mode
    {
        return Err(String::from(
            "activated authority socket does not match the protected principal binding",
        ));
    }
    Ok(())
}

fn require_managed_authority_state_absent(paths: &[String]) -> Result<(), String> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(String::from(
                    "prepared provisioning requires fresh managed authority state",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(String::from(
                    "prepared provisioning could not establish managed authority state absence",
                ));
            }
        }
    }
    Ok(())
}

fn verify_managed_authority_ancestor_chains(paths: &[String]) -> Result<(), String> {
    for path in paths {
        verify_existing_ancestor_chain_no_follow_from(Path::new("/"), Path::new(path), 0)?;
    }
    Ok(())
}

fn verify_existing_ancestor_chain_no_follow_from(
    trusted_root: &Path,
    path: &Path,
    owner_uid: u32,
) -> Result<(), String> {
    if !trusted_root.is_absolute() || !path.is_absolute() || !path.starts_with(trusted_root) {
        return Err(String::from(
            "managed authority path is outside its trusted root",
        ));
    }
    let relative = path
        .strip_prefix(trusted_root)
        .map_err(|_| String::from("managed authority path is outside its trusted root"))?;
    let mut current = trusted_root.to_path_buf();
    let mut candidates = vec![current.clone()];
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => current.push(component),
            _ => {
                return Err(String::from(
                    "managed authority path contains a non-canonical component",
                ));
            }
        }
        candidates.push(current.clone());
    }

    for (index, candidate) in candidates.iter().enumerate() {
        let metadata = match fs::symlink_metadata(candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(String::from(
                    "managed authority ancestor metadata is unavailable",
                ));
            }
        };
        let is_final = index + 1 == candidates.len();
        if metadata.file_type().is_symlink()
            || (!is_final && !metadata.is_dir())
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(String::from(
                "managed authority ancestor chain is writable or aliased",
            ));
        }
    }
    Ok(())
}

fn protected_repository_tree(
    path: &Path,
    job: &Account,
    execution: &Account,
) -> Result<PathBuf, String> {
    let root = protected_directory(path, Some(execution.uid))?;
    let mut pending = vec![root.clone()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| String::from("pressure repository entry is unavailable"))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != execution.uid
            || metadata.gid() != execution.gid
            || metadata.mode() & 0o022 != 0
            || metadata.uid() == job.uid
            || metadata.gid() == job.gid
        {
            return Err(String::from(
                "pressure repository tree is writable or aliased for the job principal",
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|_| String::from("pressure repository tree is unreadable"))?
            {
                pending.push(
                    entry
                        .map_err(|_| String::from("pressure repository tree is unreadable"))?
                        .path(),
                );
            }
        } else if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(String::from(
                "pressure repository tree contains an unsupported entry",
            ));
        }
    }
    Ok(root)
}

fn protected_root_file(path: &Path, executable: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| String::from("protected root file is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || (executable && metadata.mode() & 0o111 == 0)
    {
        return Err(String::from("protected root file identity is invalid"));
    }
    Ok(())
}

fn verify_root_protected_chain(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(String::from("protected path must be absolute"));
    }
    let mut observed = PathBuf::from("/");
    for component in path.components().filter_map(|component| match component {
        std::path::Component::Normal(value) => Some(value),
        _ => None,
    }) {
        observed.push(component);
        let metadata = fs::symlink_metadata(&observed)
            .map_err(|_| String::from("protected path ownership chain is unavailable"))?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(String::from("protected path ownership chain is invalid"));
        }
    }
    Ok(())
}

fn public_installation_evidence_identity(
    evidence: &PublicInstallationEvidenceV1,
) -> Result<String, String> {
    let mut canonical = evidence.clone();
    canonical.identity.clear();
    message_identity(PUBLIC_INSTALLATION_EVIDENCE_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| String::from("public installation evidence identity unavailable"))
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
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn pressure_source_revisions_are_exact_commit_identities() {
        assert!(validate_git_revision(&"a".repeat(40)).is_ok());
        assert!(validate_git_revision(&"A".repeat(40)).is_err());
        assert!(validate_git_revision(&"a".repeat(39)).is_err());
        assert!(validate_git_revision("not-a-revision").is_err());
    }

    #[test]
    fn public_installation_evidence_binds_every_source_revision() {
        let mut evidence = PublicInstallationEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            protocol_source_revision: "1".repeat(40),
            core_source_revision: "2".repeat(40),
            launcher_source_revision: "3".repeat(40),
            prepared_provisioning_observation: None,
            installation_manifest: ProtectedInstallationManifestV1 {
                schema_version: 1,
                identity: format!("sha256:{}", "4".repeat(64)),
                launcher_configuration_identity: format!("sha256:{}", "5".repeat(64)),
                launcher_profile_identity: format!("sha256:{}", "6".repeat(64)),
                job_principal_profile_identity: format!("sha256:{}", "7".repeat(64)),
                files: Vec::new(),
            },
        };
        let identity = public_installation_evidence_identity(&evidence).expect("public identity");
        evidence.identity = identity.clone();
        assert_eq!(
            public_installation_evidence_identity(&evidence).expect("rederived public identity"),
            identity
        );
        evidence.launcher_source_revision = "8".repeat(40);
        assert_ne!(
            public_installation_evidence_identity(&evidence).expect("changed public identity"),
            identity
        );
    }

    #[test]
    fn prepared_runner_requires_exact_publication_gate() {
        let directory = tempfile::tempdir().expect("service directory");
        let service = directory.path().join("runner.service");
        fs::write(
            &service,
            format!("[Unit]\nConditionPathExists={RUNNER_PUBLICATION_GATE}\n"),
        )
        .expect("service");
        assert!(verify_runner_publication_gate(&service, &[]).is_ok());

        fs::write(
            &service,
            "[Unit]\nConditionPathExists=/tmp/caller-controlled\n",
        )
        .expect("wrong service");
        assert!(verify_runner_publication_gate(&service, &[]).is_err());

        fs::write(
            &service,
            format!(
                "[Unit]\nConditionPathExists={RUNNER_PUBLICATION_GATE}\nConditionPathExists=/tmp/extra\n"
            ),
        )
        .expect("ambiguous service");
        assert!(verify_runner_publication_gate(&service, &[]).is_err());
    }

    #[test]
    fn prepared_provisioning_observation_identity_binds_complete_state() {
        let mut observation = PreparedProvisioningObservationV1 {
            schema_version: 1,
            identity: String::new(),
            observed_at: String::from("2026-08-15T00:00:00Z"),
            runner_service_unit: String::from("ota-authority-pressure-runner.service"),
            runner_active_state: String::from("inactive"),
            runner_sub_state: String::from("dead"),
            runner_main_pid: 0,
            runner_control_group: String::new(),
            runner_service_fragment_path: String::from(RUNNER_SERVICE),
            runner_service_drop_in_paths: vec![String::from(RUNNER_SERVICE_DROP_IN)],
            runner_executable_identity: format!("sha256:{}", "1".repeat(64)),
            runner_service_identity: format!("sha256:{}", "2".repeat(64)),
            runner_drop_in_identity: format!("sha256:{}", "3".repeat(64)),
            job_uid: 1001,
            execution_uid: 1002,
            live_principal_processes: Vec::new(),
            authority_state_posture: String::from("fresh_managed_authority_state"),
            authority_state_ancestor_posture: String::from(
                "root_owned_non_writable_directory_chain_without_aliases",
            ),
            authority_state_paths_checked: managed_authority_state_paths()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            authority_unit_posture: String::from("inactive_or_not_found_before_mutation"),
            authority_units_checked: managed_authority_units()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            authority_socket_listener_posture: String::from(
                "no_loaded_systemd_socket_unit_owns_managed_path_before_mutation",
            ),
            authority_socket_paths_checked: managed_authority_socket_paths()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        };
        let identity =
            prepared_provisioning_observation_identity(&observation).expect("observation identity");
        observation.identity = identity.clone();
        assert_eq!(
            prepared_provisioning_observation_identity(&observation)
                .expect("rederived observation identity"),
            identity
        );
        observation.authority_state_posture = String::from("existing_state");
        assert_ne!(
            prepared_provisioning_observation_identity(&observation)
                .expect("changed observation identity"),
            identity
        );
    }

    #[test]
    fn managed_authority_state_absence_rejects_dangling_symlinks() {
        let directory = tempfile::tempdir().expect("state directory");
        let state = directory.path().join("managed-state");
        symlink(directory.path().join("missing-target"), &state).expect("dangling state alias");
        assert!(
            require_managed_authority_state_absent(&[state.to_string_lossy().into_owned()])
                .is_err()
        );

        fs::remove_file(&state).expect("remove alias");
        assert!(
            require_managed_authority_state_absent(&[state.to_string_lossy().into_owned()]).is_ok()
        );
    }

    #[test]
    fn managed_authority_unit_inventory_covers_every_activated_socket_and_service() {
        assert_eq!(
            managed_authority_units(),
            [
                "ota-authority-launcher.service",
                "ota-authority-launcher.socket",
                "ota-authority-attestor.service",
                "ota-authority-attestor.socket",
                "ota-authority-broker-proxy.service",
                "ota-authority-broker-proxy.socket",
                "ota-authority-history.service",
                "ota-authority-history.socket",
            ]
        );
    }

    #[test]
    fn systemd_socket_inventory_retains_duplicate_path_owners() {
        let sockets = parse_systemd_socket_units(
            "/run/ota/authority-launcher.sock ota-authority-launcher.socket ota-authority-launcher.service\n\
             /run/ota/authority-launcher.sock ota-authority-scope-pressure.socket ota-authority-scope-pressure.service\n\
             /run/ota/authority-history.sock ota-authority-history.socket ota-authority-history.service\n",
        );
        assert_eq!(
            sockets.get(LAUNCHER_SOCKET),
            Some(&vec![
                String::from("ota-authority-launcher.socket"),
                String::from("ota-authority-scope-pressure.socket"),
            ])
        );
        assert_eq!(
            sockets.get(HISTORY_SOCKET_PATH),
            Some(&vec![String::from("ota-authority-history.socket")])
        );
    }

    #[test]
    fn managed_authority_ancestor_chain_rejects_symlinked_parent() {
        let directory = tempfile::tempdir().expect("trusted root");
        let metadata = fs::symlink_metadata(directory.path()).expect("trusted root metadata");
        let redirected = directory.path().join("redirected");
        fs::create_dir(&redirected).expect("redirect target");
        let alias = directory.path().join("authority");
        symlink(&redirected, &alias).expect("authority parent alias");
        let managed = alias.join("state.json");
        assert!(
            verify_existing_ancestor_chain_no_follow_from(
                directory.path(),
                &managed,
                metadata.uid(),
            )
            .is_err()
        );

        fs::remove_file(&alias).expect("remove alias");
        fs::create_dir(&alias).expect("authority parent");
        assert!(
            verify_existing_ancestor_chain_no_follow_from(
                directory.path(),
                &managed,
                metadata.uid(),
            )
            .is_ok()
        );
    }

    #[test]
    fn repository_truth_rejects_recursive_write_and_alias_surfaces() {
        let root = tempfile::tempdir().expect("repository");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("root mode");
        let contract = root.path().join("ota.yaml");
        fs::write(&contract, "version: 1\n").expect("contract");
        fs::set_permissions(&contract, fs::Permissions::from_mode(0o644)).expect("contract mode");
        let metadata = fs::metadata(root.path()).expect("metadata");
        let execution = Account {
            name: String::from("execution"),
            uid: metadata.uid(),
            gid: metadata.gid(),
            group: String::from("execution"),
        };
        let job = Account {
            name: String::from("job"),
            uid: metadata.uid().saturating_add(1),
            gid: metadata.gid().saturating_add(1),
            group: String::from("job"),
        };
        assert!(protected_repository_tree(root.path(), &job, &execution).is_ok());

        fs::set_permissions(&contract, fs::Permissions::from_mode(0o666)).expect("writable mode");
        assert!(protected_repository_tree(root.path(), &job, &execution).is_err());
        fs::set_permissions(&contract, fs::Permissions::from_mode(0o644)).expect("restore mode");

        let alias = root.path().join("alias.yaml");
        fs::hard_link(&contract, &alias).expect("hardlink");
        assert!(protected_repository_tree(root.path(), &job, &execution).is_err());
        fs::remove_file(&alias).expect("remove hardlink");

        let symlink_path = root.path().join("linked.yaml");
        symlink(&contract, &symlink_path).expect("symlink");
        assert!(protected_repository_tree(root.path(), &job, &execution).is_err());
    }

    #[test]
    fn prepared_runner_has_distinct_manifest_roles() {
        let paths = protected_role_paths(
            Path::new("/launcher"),
            Path::new("/attestor"),
            Path::new("/broker"),
            Path::new("/ota"),
            Path::new("/production-client"),
            Path::new("/github-runner"),
        );
        assert!(paths.contains(&(
            ProtectedInstallationRoleV1::JobRunnerExecutable,
            PathBuf::from("/github-runner"),
        )));
        assert!(paths.contains(&(
            ProtectedInstallationRoleV1::ProductionClientExecutable,
            PathBuf::from("/production-client"),
        )));
    }

    #[test]
    fn generated_units_preserve_the_protected_selected_execution_boundary() {
        let service = launcher_service_unit(
            Path::new("/usr/lib/ota-authority/bin/ota-authority-launcher"),
            Path::new("/srv/ota-pressure"),
            &[String::from("/etc/ota")],
        );
        assert!(service.contains("serve-systemd"));
        assert!(service.contains("RestrictSUIDSGID=no"));
        assert!(service.contains("AmbientCapabilities=CAP_SETUID"));
        assert!(service.contains("RuntimeDirectory=ota/authority-launcher"));
        assert!(service.contains("RuntimeDirectoryMode=0700"));
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
        assert!(protected_directories().contains(&(HISTORY_BLOB_ROOT, 0o700)));
        assert!(protected_directories().contains(&(HISTORY_CATALOG_ROOT, 0o700)));
        assert!(
            history_service_unit(Path::new("/usr/lib/ota-authority/bin/launcher"))
                .contains("serve-history")
        );
        assert!(history_socket_unit("execution").contains(&format!(
            "ListenStream={HISTORY_SOCKET_PATH}\nSocketUser=root\nSocketGroup=execution\nSocketMode=0660"
        )));
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
                false,
            )
            .contains("-- run governed --grant release --receipt")
        );
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
                Path::new("/usr/lib/ota-authority/bin/ota-authority-systemd-client"),
                true,
            )
            .contains("--json -- run governed --grant release --receipt")
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

    #[test]
    fn catalog_namespace_uses_the_content_addressed_digest_name() {
        let digest = "a".repeat(64);
        assert_eq!(
            catalog_namespace_directory(&format!("sha256:{digest}")).expect("namespace directory"),
            Path::new(HISTORY_CATALOG_ROOT).join(&digest)
        );
        assert!(catalog_namespace_directory(&format!("sha256:AA{}", "a".repeat(62))).is_err());
        assert!(catalog_namespace_directory(&digest).is_err());
    }
}
