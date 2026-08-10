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

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

//! Separately protected V3 attestation producer.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use ota_authority_protocol::{
    ATTESTATION_RESPONSE_DOMAIN_V3, LauncherAttestationPayloadV3,
    LauncherAttestationProducerBindingV1, LauncherAttestationSigningRequestV1,
    LauncherAttestationSigningResponseV1, SignedLauncherAttestationV3, domain_separated,
    launcher_attestation_claims_v3, launcher_attestation_claims_v3_identity,
    launcher_attestation_producer_binding_v1_identity,
    launcher_attestation_signing_response_v1_identity, sha256_identity,
    validate_launcher_attestation_producer_binding_v1,
    validate_launcher_attestation_signing_request_v1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
#[cfg(target_os = "linux")]
use zbus::blocking::{Proxy, connection::Builder};
#[cfg(target_os = "linux")]
use zbus::zvariant::OwnedObjectPath;

pub const ATTESTOR_CONFIG_PATH: &str = "/etc/ota/authority-attestor.json";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestorError {
    #[error("protected attestor configuration is unavailable")]
    ConfigUnavailable,
    #[error("protected attestor configuration is malformed")]
    ConfigMalformed,
    #[error("protected attestor configuration failed filesystem verification")]
    ConfigUnprotected,
    #[error("protected attestor signing credential is unavailable")]
    CredentialUnavailable,
    #[error("protected attestor signing credential does not match its binding")]
    CredentialMismatch,
    #[error("attestation signing request is invalid")]
    InvalidRequest,
    #[error("attestation signing request is expired or outside key validity")]
    InvalidFreshness,
    #[error("attestation issuance state is unavailable or uncertain")]
    StateUnavailable,
    #[error("attestation producer transport is unavailable")]
    TransportUnavailable,
    #[error("the protected attestation producer supports Linux only")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestorConfigV1 {
    schema_version: u32,
    binding: LauncherAttestationProducerBindingV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PersistedIssuanceV1 {
    schema_version: u32,
    request_identity: String,
    claims_identity: String,
    request: LauncherAttestationSigningRequestV1,
    response_bytes: Vec<u8>,
}

struct AttestationIssuer {
    binding: LauncherAttestationProducerBindingV1,
    signing_key: SigningKey,
}

impl AttestationIssuer {
    fn new(
        binding: LauncherAttestationProducerBindingV1,
        signing_key: SigningKey,
    ) -> Result<Self, AttestorError> {
        validate_launcher_attestation_producer_binding_v1(&binding)
            .map_err(|_| AttestorError::ConfigMalformed)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(&binding.signing_public_key)
            .map_err(|_| AttestorError::ConfigMalformed)?;
        if public_key.as_slice() != signing_key.verifying_key().to_bytes()
            || sha256_identity(&public_key) != binding.signing_public_key_identity
        {
            return Err(AttestorError::CredentialMismatch);
        }
        Ok(Self {
            binding,
            signing_key,
        })
    }

    fn validate_request(
        &self,
        request: &LauncherAttestationSigningRequestV1,
    ) -> Result<(), AttestorError> {
        validate_launcher_attestation_signing_request_v1(request)
            .map_err(|_| AttestorError::InvalidRequest)?;
        if request.producer_binding_identity != self.binding.identity
            || request.launcher_service_binding_identity
                != self.binding.launcher_service_binding_identity
            || request.launcher_configuration_identity
                != self.binding.launcher_configuration_identity
            || request.launcher_executable_identity != self.binding.launcher_executable_identity
            || request.launcher_profile_identity != self.binding.launcher_profile_identity
            || request.producer_audience != self.binding.audience
            || request.claims.issuer != self.binding.issuer
            || request.claims.audience != self.binding.audience
        {
            return Err(AttestorError::InvalidRequest);
        }
        Ok(())
    }

    fn issue(
        &self,
        request: &LauncherAttestationSigningRequestV1,
        now: OffsetDateTime,
    ) -> Result<LauncherAttestationSigningResponseV1, AttestorError> {
        self.validate_request(request)?;
        let not_before = parse_timestamp(&self.binding.signing_key_not_before)?;
        let not_after = parse_timestamp(&self.binding.signing_key_not_after)?;
        let now = now
            .replace_nanosecond(0)
            .map_err(|_| AttestorError::InvalidFreshness)?;
        if now < not_before || now >= not_after {
            return Err(AttestorError::InvalidFreshness);
        }
        let requested = time::Duration::seconds(
            i64::try_from(request.requested_maximum_validity_seconds)
                .map_err(|_| AttestorError::InvalidFreshness)?,
        );
        let protected = time::Duration::seconds(
            i64::try_from(self.binding.maximum_attestation_age_seconds)
                .map_err(|_| AttestorError::InvalidFreshness)?,
        );
        let verifier = time::Duration::seconds(
            i64::try_from(self.binding.verifier_maximum_age_seconds)
                .map_err(|_| AttestorError::InvalidFreshness)?,
        );
        let expires_at = std::cmp::min(
            std::cmp::min(
                std::cmp::min(
                    now.checked_add(requested)
                        .ok_or(AttestorError::InvalidFreshness)?,
                    now.checked_add(protected)
                        .ok_or(AttestorError::InvalidFreshness)?,
                ),
                now.checked_add(verifier)
                    .ok_or(AttestorError::InvalidFreshness)?,
            ),
            not_after,
        );
        if expires_at <= now {
            return Err(AttestorError::InvalidFreshness);
        }

        let claims = &request.claims;
        let payload = LauncherAttestationPayloadV3 {
            message_kind: claims.message_kind.clone(),
            attestation_protocol_version: claims.attestation_protocol_version.clone(),
            binding_identity: claims.binding_identity.clone(),
            challenge_nonce_commitment: claims.challenge_nonce_commitment.clone(),
            invocation_id: claims.invocation_id.clone(),
            work_unit_identity: claims.work_unit_identity.clone(),
            semantic_scope_identity: claims.semantic_scope_identity.clone(),
            runner_principal: claims.runner_principal.clone(),
            channel_delivery: claims.channel_delivery.clone(),
            authenticated_origin: claims.authenticated_origin.clone(),
            authority_mounts: claims.authority_mounts.clone(),
            systemd_protected_launcher: claims.systemd_protected_launcher.clone(),
            issuer: claims.issuer.clone(),
            audience: claims.audience.clone(),
            issued_at: now
                .format(&Rfc3339)
                .map_err(|_| AttestorError::InvalidFreshness)?,
            expires_at: expires_at
                .format(&Rfc3339)
                .map_err(|_| AttestorError::InvalidFreshness)?,
        };
        let canonical = serde_jcs::to_vec(&payload).map_err(|_| AttestorError::InvalidRequest)?;
        let signature = self.signing_key.sign(&domain_separated(
            ATTESTATION_RESPONSE_DOMAIN_V3.as_bytes(),
            &canonical,
        ));
        let attestation = SignedLauncherAttestationV3 {
            payload,
            key_id: self.binding.signing_key_id.clone(),
            algorithm: String::from("ed25519"),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        if launcher_attestation_claims_v3_identity(&launcher_attestation_claims_v3(&attestation))
            .map_err(|_| AttestorError::InvalidRequest)?
            != request.claims_identity
        {
            return Err(AttestorError::InvalidRequest);
        }
        let mut response = LauncherAttestationSigningResponseV1 {
            schema_version: 1,
            message_kind: ota_authority_protocol::LAUNCHER_ATTESTATION_SIGNING_RESPONSE.into(),
            request_identity: request.request_identity.clone(),
            claims_identity: request.claims_identity.clone(),
            attestation,
            response_identity: String::new(),
        };
        response.response_identity = launcher_attestation_signing_response_v1_identity(&response)
            .map_err(|_| AttestorError::InvalidRequest)?;
        Ok(response)
    }

    fn issue_durable<F>(
        &self,
        request: &LauncherAttestationSigningRequestV1,
        now: OffsetDateTime,
        mut revalidate_peer: F,
    ) -> Result<Vec<u8>, AttestorError>
    where
        F: FnMut() -> Result<(), AttestorError>,
    {
        self.validate_request(request)?;
        let directory = Path::new(&self.binding.issuance_state_directory);
        verify_protected_directory(directory)?;
        let lock_path = directory.join("issuance.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| AttestorError::StateUnavailable)?;
        verify_open_state_file(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(AttestorError::StateUnavailable);
        }

        let state_path = directory.join(format!(
            "{}.json",
            request
                .request_identity
                .strip_prefix("sha256:")
                .ok_or(AttestorError::InvalidRequest)?
        ));
        if state_path.exists() {
            let state_file = open_protected_regular_file(&state_path, 0)
                .map_err(|_| AttestorError::StateUnavailable)?;
            let persisted: PersistedIssuanceV1 =
                serde_json::from_reader(BufReader::new(state_file))
                    .map_err(|_| AttestorError::StateUnavailable)?;
            let response: LauncherAttestationSigningResponseV1 =
                serde_json::from_slice(&persisted.response_bytes)
                    .map_err(|_| AttestorError::StateUnavailable)?;
            let canonical_response =
                serde_jcs::to_vec(&response).map_err(|_| AttestorError::StateUnavailable)?;
            let expires_at = parse_timestamp(&response.attestation.payload.expires_at)
                .map_err(|_| AttestorError::StateUnavailable)?;
            if persisted.schema_version != 1
                || persisted.request_identity != request.request_identity
                || persisted.claims_identity != request.claims_identity
                || persisted.request != *request
                || persisted.response_bytes != canonical_response
                || expires_at <= now
                || ota_authority_protocol::validate_launcher_attestation_signing_response_v1(
                    &response,
                )
                .is_err()
            {
                return Err(AttestorError::StateUnavailable);
            }
            revalidate_peer()?;
            return Ok(persisted.response_bytes);
        }

        revalidate_peer()?;
        let response = self.issue(request, now)?;
        let response_bytes =
            serde_jcs::to_vec(&response).map_err(|_| AttestorError::StateUnavailable)?;
        let persisted = PersistedIssuanceV1 {
            schema_version: 1,
            request_identity: request.request_identity.clone(),
            claims_identity: request.claims_identity.clone(),
            request: request.clone(),
            response_bytes: response_bytes.clone(),
        };
        let bytes = serde_jcs::to_vec(&persisted).map_err(|_| AttestorError::StateUnavailable)?;
        let temporary_path = directory.join(format!(
            ".{}.{}.tmp",
            request
                .request_identity
                .strip_prefix("sha256:")
                .ok_or(AttestorError::InvalidRequest)?,
            std::process::id()
        ));
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)
            .map_err(|_| AttestorError::StateUnavailable)?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.sync_all())
            .map_err(|_| AttestorError::StateUnavailable)?;
        std::fs::rename(&temporary_path, &state_path)
            .map_err(|_| AttestorError::StateUnavailable)?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AttestorError::StateUnavailable)?;
        Ok(response_bytes)
    }
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, AttestorError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AttestorError::ConfigMalformed)
}

fn read_config() -> Result<AttestorConfigV1, AttestorError> {
    let path = Path::new(ATTESTOR_CONFIG_PATH);
    let file = open_protected_regular_file(path, 0)?;
    let config: AttestorConfigV1 = serde_json::from_reader(BufReader::new(file))
        .map_err(|_| AttestorError::ConfigMalformed)?;
    if config.schema_version != 1
        || launcher_attestation_producer_binding_v1_identity(&config.binding)
            .map_err(|_| AttestorError::ConfigMalformed)?
            != config.binding.identity
    {
        return Err(AttestorError::ConfigMalformed);
    }
    Ok(config)
}

fn read_signing_key(
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<SigningKey, AttestorError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or(AttestorError::CredentialUnavailable)?;
    if !directory.is_absolute() {
        return Err(AttestorError::CredentialUnavailable);
    }
    let path = directory.join(&binding.signing_credential_name);
    if path.parent() != Some(directory.as_path()) {
        return Err(AttestorError::CredentialUnavailable);
    }
    let mut file =
        open_protected_regular_file(&path, 0).map_err(|_| AttestorError::CredentialUnavailable)?;
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)
        .map_err(|_| AttestorError::CredentialUnavailable)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|_| AttestorError::CredentialUnavailable)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AttestorError::CredentialUnavailable)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn open_protected_regular_file(path: &Path, owner_uid: u32) -> Result<File, AttestorError> {
    if !path.is_absolute() {
        return Err(AttestorError::ConfigUnprotected);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| AttestorError::ConfigUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| AttestorError::ConfigUnprotected)?;
    if !metadata.is_file() || metadata.uid() != owner_uid || metadata.mode() & 0o022 != 0 {
        return Err(AttestorError::ConfigUnprotected);
    }
    verify_protected_parents(path.parent().ok_or(AttestorError::ConfigUnprotected)?)?;
    Ok(file)
}

fn verify_protected_parents(path: &Path) -> Result<(), AttestorError> {
    let mut current = Some(path);
    while let Some(parent) = current {
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| AttestorError::ConfigUnprotected)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(AttestorError::ConfigUnprotected);
        }
        current = parent.parent();
    }
    Ok(())
}

fn verify_protected_directory(path: &Path) -> Result<(), AttestorError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| AttestorError::StateUnavailable)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(AttestorError::StateUnavailable);
    }
    verify_protected_parents(path.parent().ok_or(AttestorError::StateUnavailable)?)
        .map_err(|_| AttestorError::StateUnavailable)
}

fn verify_open_state_file(file: &File) -> Result<(), AttestorError> {
    let metadata = file
        .metadata()
        .map_err(|_| AttestorError::StateUnavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(AttestorError::StateUnavailable);
    }
    Ok(())
}

fn sha256_file_identity(file: &mut File) -> Result<String, AttestorError> {
    file.rewind()
        .map_err(|_| AttestorError::ConfigUnprotected)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AttestorError::ConfigUnprotected)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn verify_self_executable(expected_identity: &str) -> Result<(), AttestorError> {
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .map_err(|_| AttestorError::ConfigUnprotected)?;
    if sha256_file_identity(&mut executable)? != expected_identity {
        return Err(AttestorError::ConfigUnprotected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn serve_once() -> Result<(), AttestorError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(AttestorError::ConfigUnprotected);
    }
    let config = read_config()?;
    verify_self_executable(&config.binding.producer_executable_identity)?;
    let key = read_signing_key(&config.binding)?;
    let issuer = AttestationIssuer::new(config.binding, key)?;
    serve_linux_once(&issuer)
}

#[cfg(not(target_os = "linux"))]
pub fn serve_once() -> Result<(), AttestorError> {
    Err(AttestorError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn serve_linux_once(_issuer: &AttestationIssuer) -> Result<(), AttestorError> {
    serve_seqpacket_once(_issuer)
}

#[cfg(target_os = "linux")]
fn serve_seqpacket_once(issuer: &AttestationIssuer) -> Result<(), AttestorError> {
    let listener = take_listener(issuer.binding.socket_path.as_str())?;
    let connection = accept_connection(&listener, issuer.binding.read_write_timeout_seconds)?;
    let peer = observe_peer(&connection, &issuer.binding)?;
    let request_bytes = receive_packet(&connection, issuer.binding.maximum_request_bytes)?;
    let request: LauncherAttestationSigningRequestV1 =
        serde_json::from_slice(&request_bytes).map_err(|_| AttestorError::InvalidRequest)?;
    validate_launcher_attestation_signing_request_v1(&request)
        .map_err(|_| AttestorError::InvalidRequest)?;
    reject_queued_packet(&connection)?;
    revalidate_peer(&connection, &peer, &issuer.binding)?;
    reject_queued_packet(&connection)?;
    let response = issuer.issue_durable(&request, OffsetDateTime::now_utc(), || {
        revalidate_peer(&connection, &peer, &issuer.binding)
    })?;
    revalidate_peer(&connection, &peer, &issuer.binding)?;
    send_packet(&connection, &response)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ObservedPeer {
    pidfd: OwnedFd,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
    process_start_identity: String,
    executable_identity: String,
    unit_object_path: String,
    control_group: String,
}

#[cfg(target_os = "linux")]
fn take_listener(expected_path: &str) -> Result<OwnedFd, AttestorError> {
    const LISTENER_FD: i32 = 3;
    if unsafe { libc::fcntl(LISTENER_FD, libc::F_GETFD) } < 0
        || unsafe { libc::fcntl(LISTENER_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
    {
        return Err(AttestorError::TransportUnavailable);
    }
    let mut socket_type = 0_i32;
    let mut socket_type_length = std::mem::size_of::<i32>() as libc::socklen_t;
    let mut accepting = 0_i32;
    let mut accepting_length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            LISTENER_FD,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            &mut socket_type_length,
        )
    } != 0
        || unsafe {
            libc::getsockopt(
                LISTENER_FD,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                std::ptr::addr_of_mut!(accepting).cast(),
                &mut accepting_length,
            )
        } != 0
        || socket_type != libc::SOCK_SEQPACKET
        || accepting != 1
    {
        return Err(AttestorError::TransportUnavailable);
    }
    verify_listener_path(LISTENER_FD, expected_path)?;
    // SAFETY: descriptor 3 is valid, uniquely consumed by this one-shot service, and now CLOEXEC.
    Ok(unsafe { OwnedFd::from_raw_fd(LISTENER_FD) })
}

#[cfg(target_os = "linux")]
fn verify_listener_path(descriptor: i32, expected_path: &str) -> Result<(), AttestorError> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            descriptor,
            std::ptr::addr_of_mut!(address).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(AttestorError::TransportUnavailable);
    }
    let path_length = usize::try_from(length)
        .map_err(|_| AttestorError::TransportUnavailable)?
        .checked_sub(std::mem::size_of::<libc::sa_family_t>())
        .ok_or(AttestorError::TransportUnavailable)?
        .min(address.sun_path.len());
    let path_bytes = &address.sun_path[..path_length];
    let terminator = path_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path_bytes.len());
    let observed = String::from_utf8(
        path_bytes[..terminator]
            .iter()
            .map(|byte| byte.to_ne_bytes()[0])
            .collect(),
    )
    .map_err(|_| AttestorError::TransportUnavailable)?;
    if observed != expected_path {
        return Err(AttestorError::TransportUnavailable);
    }
    let metadata = std::fs::symlink_metadata(expected_path)
        .map_err(|_| AttestorError::TransportUnavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(AttestorError::TransportUnavailable);
    }
    verify_protected_parents(
        Path::new(expected_path)
            .parent()
            .ok_or(AttestorError::TransportUnavailable)?,
    )
    .map_err(|_| AttestorError::TransportUnavailable)
}

#[cfg(target_os = "linux")]
fn accept_connection(listener: &OwnedFd, timeout_seconds: u64) -> Result<OwnedFd, AttestorError> {
    let descriptor = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(AttestorError::TransportUnavailable);
    }
    // SAFETY: accept4 returned a new owned descriptor.
    let connection = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let timeout = libc::timeval {
        tv_sec: i64::try_from(timeout_seconds).map_err(|_| AttestorError::TransportUnavailable)?,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                connection.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                std::ptr::addr_of!(timeout).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(AttestorError::TransportUnavailable);
        }
    }
    Ok(connection)
}

#[cfg(target_os = "linux")]
fn receive_packet(connection: &OwnedFd, maximum: usize) -> Result<Vec<u8>, AttestorError> {
    if maximum == 0 {
        return Err(AttestorError::TransportUnavailable);
    }
    let mut buffer = vec![0_u8; maximum];
    let mut control = [0_u8; 64];
    let mut vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(vector);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let observed = unsafe {
        libc::recvmsg(
            connection.as_raw_fd(),
            &mut message,
            libc::MSG_TRUNC | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if observed <= 0
        || observed as usize > maximum
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || message.msg_controllen != 0
    {
        return Err(AttestorError::TransportUnavailable);
    }
    buffer.truncate(observed as usize);
    Ok(buffer)
}

#[cfg(target_os = "linux")]
fn reject_queued_packet(connection: &OwnedFd) -> Result<(), AttestorError> {
    let mut byte = 0_u8;
    let observed = unsafe {
        libc::recv(
            connection.as_raw_fd(),
            std::ptr::addr_of_mut!(byte).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if observed > 0 {
        return Err(AttestorError::TransportUnavailable);
    }
    if observed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN) {
        return Err(AttestorError::TransportUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_packet(connection: &OwnedFd, bytes: &[u8]) -> Result<(), AttestorError> {
    let written = unsafe {
        libc::send(
            connection.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written < 0 || written as usize != bytes.len() {
        return Err(AttestorError::TransportUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn observe_peer(
    connection: &OwnedFd,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<ObservedPeer, AttestorError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    } != 0
        || credentials.uid != 0
        || credentials.gid != 0
        || credentials.pid <= 0
    {
        return Err(AttestorError::TransportUnavailable);
    }
    let pidfd = socket_peer_pidfd(connection)?;
    require_live_pidfd(&pidfd)?;
    let process_start_identity = process_start_identity(credentials.pid)?;
    let executable_identity = process_executable_identity(credentials.pid)?;
    if executable_identity != binding.launcher_executable_identity {
        return Err(AttestorError::TransportUnavailable);
    }
    let (unit_object_path, control_group) = systemd_unit_for_pid(credentials.pid, binding)?;
    Ok(ObservedPeer {
        pidfd,
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
        process_start_identity,
        executable_identity,
        unit_object_path,
        control_group,
    })
}

#[cfg(target_os = "linux")]
fn revalidate_peer(
    connection: &OwnedFd,
    expected: &ObservedPeer,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(), AttestorError> {
    require_live_pidfd(&expected.pidfd)?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    } != 0
        || credentials.pid != expected.pid
        || credentials.uid != expected.uid
        || credentials.gid != expected.gid
        || process_start_identity(expected.pid)? != expected.process_start_identity
        || process_executable_identity(expected.pid)? != expected.executable_identity
        || systemd_unit_for_pid(expected.pid, binding)?
            != (
                expected.unit_object_path.clone(),
                expected.control_group.clone(),
            )
    {
        return Err(AttestorError::TransportUnavailable);
    }
    require_live_pidfd(&expected.pidfd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn socket_peer_pidfd(connection: &OwnedFd) -> Result<OwnedFd, AttestorError> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut descriptor = -1_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            std::ptr::addr_of_mut!(descriptor).cast(),
            &mut length,
        )
    } != 0
        || descriptor < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        if descriptor >= 0 {
            unsafe { libc::close(descriptor) };
        }
        return Err(AttestorError::TransportUnavailable);
    }
    // SAFETY: SO_PEERPIDFD returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn require_live_pidfd(pidfd: &OwnedFd) -> Result<(), AttestorError> {
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(AttestorError::TransportUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_start_identity(pid: libc::pid_t) -> Result<String, AttestorError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| AttestorError::TransportUnavailable)?;
    let closing = stat.rfind(')').ok_or(AttestorError::TransportUnavailable)?;
    let start_time = stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(AttestorError::TransportUnavailable)?;
    Ok(sha256_identity(
        format!("pid:{pid};start_time:{start_time}").as_bytes(),
    ))
}

#[cfg(target_os = "linux")]
fn process_executable_identity(pid: libc::pid_t) -> Result<String, AttestorError> {
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/exe"))
        .map_err(|_| AttestorError::TransportUnavailable)?;
    sha256_file_identity(&mut executable).map_err(|_| AttestorError::TransportUnavailable)
}

#[cfg(target_os = "linux")]
fn systemd_unit_for_pid(
    pid: libc::pid_t,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(String, String), AttestorError> {
    const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
    const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
    const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
    const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
    let bus = std::fs::symlink_metadata("/run/dbus/system_bus_socket")
        .map_err(|_| AttestorError::TransportUnavailable)?;
    if !bus.file_type().is_socket() || bus.uid() != 0 || bus.mode() & 0o022 != 0 {
        return Err(AttestorError::TransportUnavailable);
    }
    let connection = Builder::address(SYSTEM_BUS_ADDRESS)
        .and_then(Builder::build)
        .map_err(|_| AttestorError::TransportUnavailable)?;
    let manager = Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| AttestorError::TransportUnavailable)?;
    let unit_path: OwnedObjectPath = manager
        .call("GetUnitByPID", &(pid as u32,))
        .map_err(|_| AttestorError::TransportUnavailable)?;
    let unit = Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        unit_path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .map_err(|_| AttestorError::TransportUnavailable)?;
    let id: String = unit
        .get_property("Id")
        .map_err(|_| AttestorError::TransportUnavailable)?;
    let control_group: String = unit
        .get_property("ControlGroup")
        .map_err(|_| AttestorError::TransportUnavailable)?;
    if id != binding.launcher_service_unit || control_group.is_empty() {
        return Err(AttestorError::TransportUnavailable);
    }
    let proc_cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| AttestorError::TransportUnavailable)?;
    if !proc_cgroup
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(control_group.as_str()))
    {
        return Err(AttestorError::TransportUnavailable);
    }
    Ok((unit_path.to_string(), control_group))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    use ed25519_dalek::{Signature, Verifier};
    #[cfg(target_os = "linux")]
    use ota_authority_protocol::{
        ATTESTATION_RESPONSE, BrokerChallenge, CHALLENGE_REQUEST, LauncherAttestationClaimsV3,
        LauncherAttestationProducerBindingV1, LauncherAttestationSigningRequestV1,
        LauncherPrincipalMappingV1, OtaProcessPostureV1, PROTOCOL_VERSION_V1,
        RuntimeBoundaryObservationState, SYSTEMD_ATTESTOR_SERVICE_UNIT_V1,
        SYSTEMD_ATTESTOR_SOCKET_PATH_V1, SYSTEMD_LAUNCHER_SERVICE_UNIT_V1,
        SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1, SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3,
        SystemdJobPrincipalObservation, SystemdLauncherObservation,
        SystemdProtectedLauncherInstanceEvidenceV1, SystemdProtectedLauncherInstanceEvidenceV2,
        UnixPrincipalIdentity, domain_separated, launcher_attestation_claims_v3,
        launcher_attestation_claims_v3_identity, launcher_attestation_producer_binding_v1_identity,
        launcher_attestation_signing_request_v1_identity, launcher_principal_mapping_identity,
        ota_process_posture_identity, sha256_identity, systemd_job_principal_profile_identity,
        systemd_job_principal_profile_v1, systemd_launcher_profile_identity,
        systemd_launcher_profile_v1, systemd_protected_launcher_instance_identity,
        systemd_protected_launcher_instance_v2_identity,
    };
    #[test]
    fn unsupported_host_never_claims_a_protected_service() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(serve_once(), Err(AttestorError::UnsupportedPlatform));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn producer_issues_once_with_deterministic_freshness_and_projection() {
        let state = tempfile::tempdir_in("/root").expect("protected temporary state");
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
            .expect("state permissions");
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut binding = producer_binding(state.path(), &signing_key);
        binding.identity = launcher_attestation_producer_binding_v1_identity(&binding)
            .expect("producer binding identity");
        let issuer = AttestationIssuer::new(binding.clone(), signing_key.clone()).expect("issuer");
        let request = signing_request(&binding);
        let now = OffsetDateTime::parse("2026-08-10T12:00:00Z", &Rfc3339).expect("fixed test time");

        assert_eq!(
            issuer.issue_durable(&request, now, || Err(AttestorError::TransportUnavailable)),
            Err(AttestorError::TransportUnavailable)
        );
        assert_eq!(
            std::fs::read_dir(state.path())
                .expect("state directory")
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "json"))
                .count(),
            0
        );
        let first_bytes = issuer
            .issue_durable(&request, now, || Ok(()))
            .expect("first durable issuance");
        assert_eq!(
            issuer.issue_durable(&request, now, || Err(AttestorError::TransportUnavailable)),
            Err(AttestorError::TransportUnavailable)
        );
        let replay_bytes = issuer
            .issue_durable(&request, now + time::Duration::seconds(10), || Ok(()))
            .expect("idempotent replay");
        assert_eq!(first_bytes, replay_bytes);
        let first: LauncherAttestationSigningResponseV1 =
            serde_json::from_slice(&first_bytes).expect("canonical response");
        assert_eq!(first.attestation.payload.issued_at, "2026-08-10T12:00:00Z");
        assert_eq!(first.attestation.payload.expires_at, "2026-08-10T12:01:30Z");
        assert_eq!(
            launcher_attestation_claims_v3(&first.attestation),
            request.claims
        );
        let payload = serde_jcs::to_vec(&first.attestation.payload).expect("signed payload");
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&first.attestation.signature)
            .expect("signature encoding");
        let signature = Signature::from_slice(&signature_bytes).expect("signature");
        signing_key
            .verifying_key()
            .verify(
                &domain_separated(ATTESTATION_RESPONSE_DOMAIN_V3.as_bytes(), &payload),
                &signature,
            )
            .expect("signature verifies");
        #[cfg(feature = "protected-attestor-client")]
        {
            crate::attestation_client::verify_response(
                &binding,
                &request,
                &first,
                now + time::Duration::seconds(10),
            )
            .expect("launcher independently verifies producer response");
            let mut substituted = first.clone();
            substituted.attestation.payload.semantic_scope_identity = identity('1');
            substituted.claims_identity = launcher_attestation_claims_v3_identity(
                &launcher_attestation_claims_v3(&substituted.attestation),
            )
            .expect("substituted claims identity");
            substituted.response_identity =
                launcher_attestation_signing_response_v1_identity(&substituted)
                    .expect("substituted envelope identity");
            assert_eq!(
                crate::attestation_client::verify_response(
                    &binding,
                    &request,
                    &substituted,
                    now + time::Duration::seconds(10),
                ),
                Err(crate::attestation_client::AttestationClientError::InvalidResponse)
            );
        }

        let mut substituted = request.clone();
        substituted.requested_maximum_validity_seconds = 91;
        assert_eq!(
            issuer.issue_durable(&substituted, now, || Ok(())),
            Err(AttestorError::InvalidRequest)
        );
        assert_eq!(
            issuer.issue_durable(&request, now + time::Duration::seconds(91), || Ok(())),
            Err(AttestorError::StateUnavailable)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn producer_transport_rejects_truncation_descriptors_and_queued_requests() {
        let (sender, receiver) = seqpacket_pair();
        send_packet(&sender, b"oversized").expect("send oversized packet");
        assert_eq!(
            receive_packet(&receiver, 4),
            Err(AttestorError::TransportUnavailable)
        );

        let (sender, receiver) = seqpacket_pair();
        send_descriptor(&sender);
        assert_eq!(
            receive_packet(&receiver, 8),
            Err(AttestorError::TransportUnavailable)
        );

        let (sender, receiver) = seqpacket_pair();
        send_packet(&sender, b"first").expect("send first request");
        send_packet(&sender, b"second").expect("send second request");
        assert_eq!(
            receive_packet(&receiver, 8).expect("first packet"),
            b"first"
        );
        assert_eq!(
            reject_queued_packet(&receiver),
            Err(AttestorError::TransportUnavailable)
        );
    }

    #[cfg(target_os = "linux")]
    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1_i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: socketpair initialized two distinct owned descriptors.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    #[cfg(target_os = "linux")]
    fn send_descriptor(connection: &OwnedFd) {
        let file = File::open("/dev/null").expect("open descriptor payload");
        let mut payload = [b'x'];
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0_u8; 64];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = std::ptr::addr_of_mut!(vector);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as libc::c_uint) as usize };
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<i32>() as libc::c_uint) as usize;
            std::ptr::write(libc::CMSG_DATA(header).cast::<i32>(), file.as_raw_fd());
        }
        assert_eq!(
            unsafe { libc::sendmsg(connection.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
            1
        );
    }

    #[cfg(target_os = "linux")]
    fn producer_binding(
        state_directory: &Path,
        signing_key: &SigningKey,
    ) -> LauncherAttestationProducerBindingV1 {
        LauncherAttestationProducerBindingV1 {
            schema_version: 1,
            identity: String::new(),
            producer_id: String::from("systemd-attestor-v1"),
            socket_path: String::from(SYSTEMD_ATTESTOR_SOCKET_PATH_V1),
            service_unit: String::from(SYSTEMD_ATTESTOR_SERVICE_UNIT_V1),
            launcher_service_unit: String::from(SYSTEMD_LAUNCHER_SERVICE_UNIT_V1),
            launcher_service_binding_identity: identity('1'),
            launcher_configuration_identity: identity('2'),
            launcher_profile_identity: identity('3'),
            launcher_executable_identity: identity('4'),
            producer_executable_identity: identity('5'),
            verifier_key_set_identity: identity('6'),
            signing_key_id: String::from("systemd-attestor-2026-01"),
            signing_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            signing_public_key_identity: sha256_identity(&signing_key.verifying_key().to_bytes()),
            signing_key_not_before: String::from("2026-08-10T00:00:00Z"),
            signing_key_not_after: String::from("2026-08-11T00:00:00Z"),
            issuer: String::from("systemd-attestor"),
            audience: String::from("ota-crossing-broker"),
            maximum_attestation_age_seconds: 120,
            verifier_maximum_age_seconds: 180,
            maximum_request_bytes: ota_authority_protocol::MAX_FRAME_BYTES,
            read_write_timeout_seconds: 5,
            issuance_state_directory: state_directory.display().to_string(),
            signing_credential_name: String::from("ota-attestor-ed25519"),
        }
    }

    #[cfg(target_os = "linux")]
    fn signing_request(
        binding: &LauncherAttestationProducerBindingV1,
    ) -> LauncherAttestationSigningRequestV1 {
        let uniform = |uid: u32, gid: u32| UnixPrincipalIdentity {
            real_uid: uid,
            effective_uid: uid,
            saved_uid: uid,
            filesystem_uid: uid,
            real_gid: gid,
            effective_gid: gid,
            saved_gid: gid,
            filesystem_gid: gid,
        };
        let mut mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer: uniform(1001, 1001),
            execution: uniform(1002, 1002),
            job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job profile identity"),
            launcher_session_binding_identity: binding.launcher_service_binding_identity.clone(),
        };
        mapping.identity = launcher_principal_mapping_identity(&mapping).expect("mapping identity");
        let mut posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::OTA_PROCESS_POSTURE.into(),
            pid: 1234,
            process_start_time_identity: identity('7'),
            ota_binary_identity: identity('8'),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: mapping.identity.clone(),
        };
        posture.identity = ota_process_posture_identity(&posture).expect("posture identity");
        let mut instance = SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: mapping,
            process_posture: posture,
            systemd_launcher_profile_identity: systemd_launcher_profile_identity(
                &systemd_launcher_profile_v1(),
            )
            .expect("launcher profile identity"),
            systemd_job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job profile identity"),
            launcher_session_binding_identity: binding.launcher_service_binding_identity.clone(),
            systemd_invocation_identity: identity('9'),
            working_directory_identity: identity('a'),
            child_process_identity: identity('b'),
        };
        instance.identity =
            systemd_protected_launcher_instance_identity(&instance).expect("instance identity");
        let mut complete = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 2,
            identity: String::new(),
            instance_v1: instance,
            launcher_observations: systemd_launcher_profile_v1()
                .evidence_sources
                .into_iter()
                .map(|source| SystemdLauncherObservation {
                    source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                })
                .collect(),
            job_principal_observations: systemd_job_principal_profile_v1()
                .requirements
                .into_iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_systemd_protected_launcher"),
                })
                .collect(),
        };
        complete.identity =
            systemd_protected_launcher_instance_v2_identity(&complete).expect("complete identity");
        let claims = LauncherAttestationClaimsV3 {
            message_kind: ATTESTATION_RESPONSE.into(),
            attestation_protocol_version: SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3.into(),
            binding_identity: identity('c'),
            challenge_nonce_commitment: identity('d'),
            invocation_id: String::from("invocation-1"),
            work_unit_identity: identity('e'),
            semantic_scope_identity: identity('f'),
            runner_principal: complete.instance_v1.principal_mapping.identity.clone(),
            channel_delivery: String::from("launcher_session_fd"),
            authenticated_origin: String::from("systemd-protected-launcher"),
            authority_mounts: vec![String::from("authority-binding-v2")],
            systemd_protected_launcher: complete,
            issuer: binding.issuer.clone(),
            audience: binding.audience.clone(),
        };
        let claims_identity =
            launcher_attestation_claims_v3_identity(&claims).expect("claims identity");
        let challenge = BrokerChallenge {
            message_kind: CHALLENGE_REQUEST.into(),
            protocol_version: PROTOCOL_VERSION_V1.into(),
            binding_identity: claims.binding_identity.clone(),
            nonce_commitment: claims.challenge_nonce_commitment.clone(),
            work_unit_identity: claims.work_unit_identity.clone(),
            semantic_scope_identity: claims.semantic_scope_identity.clone(),
            contract_identity: identity('0'),
        };
        let mut request = LauncherAttestationSigningRequestV1 {
            schema_version: 1,
            message_kind: ota_authority_protocol::LAUNCHER_ATTESTATION_SIGNING_REQUEST.into(),
            request_identity: String::new(),
            challenge,
            claims_identity,
            claims,
            launcher_service_binding_identity: binding.launcher_service_binding_identity.clone(),
            launcher_configuration_identity: binding.launcher_configuration_identity.clone(),
            launcher_executable_identity: binding.launcher_executable_identity.clone(),
            launcher_profile_identity: binding.launcher_profile_identity.clone(),
            producer_binding_identity: binding.identity.clone(),
            producer_audience: binding.audience.clone(),
            requested_maximum_validity_seconds: 90,
        };
        request.request_identity =
            launcher_attestation_signing_request_v1_identity(&request).expect("request identity");
        request
    }

    #[cfg(target_os = "linux")]
    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }
}
