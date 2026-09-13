//! Descriptor-retained one-use state for the private authority-snapshot exchange.
//!
//! This state is distinct from public capability-observation replay. Reservation precedes snapshot
//! disclosure and consumption follows successful V2 binding reconciliation; failures remain
//! reserved and therefore fail closed.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ota_authority_protocol::{
    LauncherStartupContinuationV1, ProtectedAuthoritySnapshotRequestV1,
    ProtectedAuthoritySnapshotResponseV1,
    ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
    ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    protected_authority_snapshot_response_v1_identity,
    reconcile_protected_authority_snapshot_request_v1,
    reconcile_protected_authority_snapshot_response_v1,
    validate_protected_launcher_secret_delivery_transaction_binding_request_v2,
    validate_protected_launcher_secret_delivery_transaction_binding_v2,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::installation_manifest::AUTHORITY_SNAPSHOT_REPLAY_DIRECTORY;
use crate::protected_launcher_capability::{
    open_protected_directory_chain_allowing_mounts, open_root, openat2_beneath,
    openat2_beneath_with_mode,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ProtectedAuthoritySnapshotReplayError {
    #[error("protected authority snapshot replay state is unavailable or uncertain")]
    Unavailable,
    #[error("protected authority snapshot request has already been reserved")]
    ReplayDetected,
    #[error("protected authority snapshot replay state does not match the selected exchange")]
    Mismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SnapshotReplayStatusV1 {
    Reserved,
    Consumed,
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SnapshotReplayRecordV1 {
    schema_version: u32,
    request_identity: String,
    challenge_identity: String,
    startup_continuation_identity: String,
    session_identity: String,
    status: SnapshotReplayStatusV1,
    response_identity: Option<String>,
    protected_snapshot_identity: Option<String>,
    binding_request_identity: Option<String>,
    binding_identity: Option<String>,
}

pub(crate) struct ProtectedAuthoritySnapshotReservationV1 {
    record_name: String,
    request_identity: String,
    challenge_identity: String,
    startup_continuation_identity: String,
    session_identity: String,
    request: ProtectedAuthoritySnapshotRequestV1,
    startup_continuation: LauncherStartupContinuationV1,
}

pub(crate) struct ProtectedAuthoritySnapshotReplayStoreV1 {
    directory: File,
    expected_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconciledSnapshotConsumptionV1 {
    response_identity: String,
    protected_snapshot_identity: String,
    binding_request_identity: String,
    binding_identity: String,
}

#[derive(Debug, Clone)]
struct SnapshotConsumptionLinksV1 {
    response_identity: String,
    response_request_identity: String,
    payload_request_identity: String,
    payload_startup_continuation_identity: String,
    payload_session_identity: String,
    protected_snapshot_identity: String,
    binding_request_identity: String,
    binding_request_startup_continuation_identity: String,
    binding_request_session_identity: String,
    binding_request_protected_snapshot_identity: String,
    binding_response_request_identity: String,
    binding_response_protected_snapshot_identity: String,
    binding_request_identity_in_binding: String,
    binding_startup_continuation_identity: String,
    binding_session_identity: String,
    binding_protected_snapshot_identity: String,
    binding_identity: String,
}

fn reconcile_consumption_links(
    reservation: &ProtectedAuthoritySnapshotReservationV1,
    links: &SnapshotConsumptionLinksV1,
) -> Result<ReconciledSnapshotConsumptionV1, ProtectedAuthoritySnapshotReplayError> {
    if links.response_request_identity != reservation.request_identity
        || links.payload_request_identity != reservation.request_identity
        || links.payload_startup_continuation_identity != reservation.startup_continuation_identity
        || links.payload_session_identity != reservation.session_identity
        || links.binding_request_startup_continuation_identity
            != reservation.startup_continuation_identity
        || links.binding_request_session_identity != reservation.session_identity
        || links.binding_request_protected_snapshot_identity != links.protected_snapshot_identity
        || links.binding_response_request_identity != links.binding_request_identity
        || links.binding_response_protected_snapshot_identity != links.protected_snapshot_identity
        || links.binding_request_identity_in_binding != links.binding_request_identity
        || links.binding_startup_continuation_identity != reservation.startup_continuation_identity
        || links.binding_session_identity != reservation.session_identity
        || links.binding_protected_snapshot_identity != links.protected_snapshot_identity
    {
        return Err(ProtectedAuthoritySnapshotReplayError::Mismatch);
    }
    Ok(ReconciledSnapshotConsumptionV1 {
        response_identity: links.response_identity.clone(),
        protected_snapshot_identity: links.protected_snapshot_identity.clone(),
        binding_request_identity: links.binding_request_identity.clone(),
        binding_identity: links.binding_identity.clone(),
    })
}

impl ProtectedAuthoritySnapshotReplayStoreV1 {
    pub(crate) fn open() -> Result<Self, ProtectedAuthoritySnapshotReplayError> {
        let relative = Path::new(AUTHORITY_SNAPSHOT_REPLAY_DIRECTORY)
            .strip_prefix("/")
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        let root = open_root(Path::new("/"), 0, 0)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        let directory =
            open_protected_directory_chain_allowing_mounts(root.as_raw_fd(), relative, 0, 0, true)
                .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        Self::from_directory(directory.as_raw_fd(), 0)
    }

    fn from_directory(
        directory: std::os::fd::RawFd,
        expected_uid: u32,
    ) -> Result<Self, ProtectedAuthoritySnapshotReplayError> {
        let directory = openat2_beneath(
            directory,
            b".",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        Ok(Self {
            directory: File::from(directory),
            expected_uid,
        })
    }

    #[cfg(test)]
    fn open_for_test(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, ProtectedAuthoritySnapshotReplayError> {
        let directory = open_root(directory, expected_uid, expected_gid)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        Self::from_directory(directory.as_raw_fd(), expected_uid)
    }

    pub(crate) fn reserve(
        &self,
        request: &ProtectedAuthoritySnapshotRequestV1,
        startup_continuation: &LauncherStartupContinuationV1,
    ) -> Result<ProtectedAuthoritySnapshotReservationV1, ProtectedAuthoritySnapshotReplayError>
    {
        let observed_at_unix_seconds = current_time()?;
        reconcile_protected_authority_snapshot_request_v1(
            request,
            startup_continuation,
            observed_at_unix_seconds,
        )
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Mismatch)?;
        let record_name = record_name(request.identity.as_str())?;
        let lock = self.lock()?;
        let _guard = FileLockGuard(&lock);
        let record = SnapshotReplayRecordV1 {
            schema_version: 1,
            request_identity: request.identity.clone(),
            challenge_identity: request.challenge.identity.clone(),
            startup_continuation_identity: startup_continuation.identity.clone(),
            session_identity: request.session_identity.clone(),
            status: SnapshotReplayStatusV1::Reserved,
            response_identity: None,
            protected_snapshot_identity: None,
            binding_request_identity: None,
            binding_identity: None,
        };
        write_new_record(self.directory.as_raw_fd(), &record_name, &record)?;
        self.directory
            .sync_all()
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        Ok(ProtectedAuthoritySnapshotReservationV1 {
            record_name,
            request_identity: request.identity.clone(),
            challenge_identity: request.challenge.identity.clone(),
            startup_continuation_identity: startup_continuation.identity.clone(),
            session_identity: request.session_identity.clone(),
            request: request.clone(),
            startup_continuation: startup_continuation.clone(),
        })
    }

    pub(crate) fn consume(
        &self,
        reservation: &ProtectedAuthoritySnapshotReservationV1,
        response: &ProtectedAuthoritySnapshotResponseV1,
        binding_request: &ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
        binding_response: &ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    ) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
        let observed_at_unix_seconds = current_time()?;
        if reconcile_protected_authority_snapshot_response_v1(
            &reservation.request,
            response,
            &reservation.startup_continuation,
            observed_at_unix_seconds,
        )
        .is_err()
            || response.identity
                != protected_authority_snapshot_response_v1_identity(response)
                    .map_err(|_| ProtectedAuthoritySnapshotReplayError::Mismatch)?
            || validate_protected_launcher_secret_delivery_transaction_binding_request_v2(
                binding_request,
            )
            .is_err()
            || validate_protected_launcher_secret_delivery_transaction_binding_v2(
                &binding_response.binding,
            )
            .is_err()
        {
            return Err(ProtectedAuthoritySnapshotReplayError::Mismatch);
        }
        let links = SnapshotConsumptionLinksV1 {
            response_identity: response.identity.clone(),
            response_request_identity: response.request_identity.clone(),
            payload_request_identity: response.payload.request_identity.clone(),
            payload_startup_continuation_identity: response
                .payload
                .startup_continuation_identity
                .clone(),
            payload_session_identity: response.payload.session_identity.clone(),
            protected_snapshot_identity: response.protected_snapshot_identity.clone(),
            binding_request_identity: binding_request.identity.clone(),
            binding_request_startup_continuation_identity: binding_request
                .startup_continuation_identity
                .clone(),
            binding_request_session_identity: binding_request.session_identity.clone(),
            binding_request_protected_snapshot_identity: binding_request
                .protected_snapshot_identity
                .clone(),
            binding_response_request_identity: binding_response.request_identity.clone(),
            binding_response_protected_snapshot_identity: binding_response
                .protected_snapshot_identity
                .clone(),
            binding_request_identity_in_binding: binding_response.binding.request_identity.clone(),
            binding_startup_continuation_identity: binding_response
                .binding
                .startup_continuation_identity
                .clone(),
            binding_session_identity: binding_response.binding.session_identity.clone(),
            binding_protected_snapshot_identity: binding_response
                .binding
                .protected_snapshot_identity
                .clone(),
            binding_identity: binding_response.binding.identity.clone(),
        };
        let consumption = reconcile_consumption_links(reservation, &links)?;
        self.consume_reconciled(reservation, &consumption)
    }

    pub(crate) fn refuse(
        &self,
        reservation: &ProtectedAuthoritySnapshotReservationV1,
    ) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
        let lock = self.lock()?;
        let _guard = FileLockGuard(&lock);
        let mut file = File::from(
            openat2_beneath(
                self.directory.as_raw_fd(),
                reservation.record_name.as_bytes(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?,
        );
        verify_protected_file(&file, self.expected_uid)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        let mut record: SnapshotReplayRecordV1 = serde_json::from_slice(&bytes)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        if record.schema_version != 1
            || record.status != SnapshotReplayStatusV1::Reserved
            || record.request_identity != reservation.request_identity
            || record.challenge_identity != reservation.challenge_identity
            || record.startup_continuation_identity != reservation.startup_continuation_identity
            || record.session_identity != reservation.session_identity
            || record.response_identity.is_some()
            || record.protected_snapshot_identity.is_some()
            || record.binding_request_identity.is_some()
            || record.binding_identity.is_some()
        {
            return Err(ProtectedAuthoritySnapshotReplayError::Mismatch);
        }
        record.status = SnapshotReplayStatusV1::Refused;
        replace_record(
            self.directory.as_raw_fd(),
            &reservation.record_name,
            &record,
        )?;
        self.directory
            .sync_all()
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)
    }

    fn consume_reconciled(
        &self,
        reservation: &ProtectedAuthoritySnapshotReservationV1,
        consumption: &ReconciledSnapshotConsumptionV1,
    ) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
        let lock = self.lock()?;
        let _guard = FileLockGuard(&lock);
        let mut file = File::from(
            openat2_beneath(
                self.directory.as_raw_fd(),
                reservation.record_name.as_bytes(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?,
        );
        verify_protected_file(&file, self.expected_uid)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        let mut record: SnapshotReplayRecordV1 = serde_json::from_slice(&bytes)
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
        if record.schema_version != 1
            || record.status != SnapshotReplayStatusV1::Reserved
            || record.request_identity != reservation.request_identity
            || record.challenge_identity != reservation.challenge_identity
            || record.startup_continuation_identity != reservation.startup_continuation_identity
            || record.session_identity != reservation.session_identity
            || record.response_identity.is_some()
            || record.protected_snapshot_identity.is_some()
            || record.binding_request_identity.is_some()
            || record.binding_identity.is_some()
        {
            return Err(ProtectedAuthoritySnapshotReplayError::Mismatch);
        }
        record.status = SnapshotReplayStatusV1::Consumed;
        record.response_identity = Some(consumption.response_identity.clone());
        record.protected_snapshot_identity = Some(consumption.protected_snapshot_identity.clone());
        record.binding_request_identity = Some(consumption.binding_request_identity.clone());
        record.binding_identity = Some(consumption.binding_identity.clone());
        replace_record(
            self.directory.as_raw_fd(),
            &reservation.record_name,
            &record,
        )?;
        self.directory
            .sync_all()
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)
    }

    fn lock(&self) -> Result<File, ProtectedAuthoritySnapshotReplayError> {
        let file = File::from(
            openat2_beneath_with_mode(
                self.directory.as_raw_fd(),
                b"replay.lock",
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
            .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?,
        );
        verify_protected_file(&file, self.expected_uid)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(ProtectedAuthoritySnapshotReplayError::Unavailable);
        }
        Ok(file)
    }
}

struct FileLockGuard<'a>(&'a File);

impl Drop for FileLockGuard<'_> {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn current_time() -> Result<u64, ProtectedAuthoritySnapshotReplayError> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)
}

fn record_name(identity: &str) -> Result<String, ProtectedAuthoritySnapshotReplayError> {
    let digest = identity
        .strip_prefix("sha256:")
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(ProtectedAuthoritySnapshotReplayError::Mismatch)?;
    Ok(format!("{digest}.json"))
}

fn verify_protected_file(
    file: &File,
    expected_uid: u32,
) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    if !metadata.is_file() || metadata.uid() != expected_uid || metadata.mode() & 0o7777 != 0o600 {
        return Err(ProtectedAuthoritySnapshotReplayError::Unavailable);
    }
    Ok(())
}

fn write_new_record(
    directory: std::os::fd::RawFd,
    name: &str,
    record: &SnapshotReplayRecordV1,
) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
    let bytes = serde_jcs::to_vec(record)
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    let mut file = File::from(
        openat2_beneath_with_mode(
            directory,
            name.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::ReplayDetected)?,
    );
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)
}

fn replace_record(
    directory: std::os::fd::RawFd,
    name: &str,
    record: &SnapshotReplayRecordV1,
) -> Result<(), ProtectedAuthoritySnapshotReplayError> {
    let bytes = serde_jcs::to_vec(record)
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    let temporary = format!(".{name}.{}.tmp", std::process::id());
    let mut file = File::from(
        openat2_beneath_with_mode(
            directory,
            temporary.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?,
    );
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    let temporary =
        CString::new(temporary).map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    let name =
        CString::new(name).map_err(|_| ProtectedAuthoritySnapshotReplayError::Unavailable)?;
    if unsafe { libc::renameat(directory, temporary.as_ptr(), directory, name.as_ptr()) } != 0 {
        return Err(ProtectedAuthoritySnapshotReplayError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ota_authority_protocol::*;
    use tempfile::tempdir;

    use super::*;

    fn identity(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn exchange() -> (
        LauncherStartupContinuationV1,
        ProtectedAuthoritySnapshotRequestV1,
    ) {
        let mut startup = LauncherStartupContinuationV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_STARTUP_CONTINUATION.into(),
            invocation_id: "snapshot-replay-test".into(),
            launcher_request_identity: identity('1'),
            child_process_identity: identity('2'),
            working_directory_identity: identity('3'),
            process_posture_identity: identity('4'),
            principal_mapping_identity: identity('5'),
        };
        startup.identity = launcher_startup_continuation_identity(&startup).expect("startup");
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("current time");
        let nonce = [7_u8; 32];
        let mut challenge = ProtectedAuthoritySnapshotChallengeV1 {
            schema_version: 1,
            message_kind: PROTECTED_AUTHORITY_SNAPSHOT_CHALLENGE.into(),
            identity: String::new(),
            nonce_commitment: protected_authority_snapshot_nonce_commitment_v1(&nonce)
                .expect("nonce commitment"),
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + 300,
        };
        challenge.identity =
            protected_authority_snapshot_challenge_v1_identity(&challenge).expect("challenge");
        let mut request = ProtectedAuthoritySnapshotRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_AUTHORITY_SNAPSHOT_REQUEST.into(),
            identity: String::new(),
            challenge,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            launcher_request_identity: startup.launcher_request_identity.clone(),
            startup_continuation_identity: startup.identity.clone(),
            session_identity: protected_launcher_secret_delivery_transaction_session_v1_identity(
                startup.identity.as_str(),
            )
            .expect("session"),
            contract_identity: identity('6'),
            selected_execution_graph_identity: identity('7'),
        };
        request.identity =
            protected_authority_snapshot_request_v1_identity(&request).expect("request");
        (startup, request)
    }

    fn replay_fixture() -> (
        tempfile::TempDir,
        ProtectedAuthoritySnapshotReplayStoreV1,
        ProtectedAuthoritySnapshotReservationV1,
    ) {
        let directory = tempdir().expect("replay directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let metadata = directory.path().metadata().expect("metadata");
        let store = ProtectedAuthoritySnapshotReplayStoreV1::open_for_test(
            directory.path(),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("replay store");
        let (startup, request) = exchange();
        let reservation = store.reserve(&request, &startup).expect("reservation");
        (directory, store, reservation)
    }

    fn protocol_replay_fixture() -> (
        tempfile::TempDir,
        ProtectedAuthoritySnapshotReplayStoreV1,
        ProtectedAuthoritySnapshotReservationV1,
        ProtectedAuthoritySnapshotResponseV1,
        ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
        ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    ) {
        let directory = tempdir().expect("replay directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let metadata = directory.path().metadata().expect("metadata");
        let store = ProtectedAuthoritySnapshotReplayStoreV1::open_for_test(
            directory.path(),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("replay store");
        let (startup, request) = exchange();
        let reservation = store.reserve(&request, &startup).expect("reservation");
        let (response, binding_request, binding_response) = protocol_records(&startup, &request);
        (
            directory,
            store,
            reservation,
            response,
            binding_request,
            binding_response,
        )
    }

    pub(crate) fn relay_protocol_fixture() -> (
        ProtectedLauncherCapabilityObservationRequestV1,
        ota_authority_protocol::ProtectedLauncherCapabilityObservationResponseV1,
        ota_authority_protocol::ProtectedSameChildCapabilityPreludeV1,
        ProtectedAuthoritySnapshotRequestV1,
        ProtectedAuthoritySnapshotResponseV1,
        ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
        ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    ) {
        let (_, _, reservation, snapshot_response, binding_request, binding_response) =
            protocol_replay_fixture();
        let observation = binding_request.observation.clone();
        let mut prelude = ota_authority_protocol::ProtectedSameChildCapabilityPreludeV1 {
            schema_version: 1,
            record_kind: ota_authority_protocol::PROTECTED_SAME_CHILD_CAPABILITY_PRELUDE.into(),
            identity: String::new(),
            observation_request_identity: observation.identity.clone(),
            projection_identity: binding_response.projection.projection_identity.clone(),
            protected_capability_identity: binding_response
                .binding
                .protected_capability_identity
                .clone(),
            verifier_identity: binding_response.binding.verifier_identity.clone(),
            installation_evidence_identity: binding_response
                .binding
                .installation_evidence_identity
                .clone(),
            launcher_request_identity: binding_request.launcher_request_identity.clone(),
            startup_continuation_identity: binding_request.startup_continuation_identity.clone(),
            session_identity: binding_request.session_identity.clone(),
            expires_at_unix_seconds: observation.challenge.expires_at_unix_seconds,
        };
        prelude.identity =
            ota_authority_protocol::protected_same_child_capability_prelude_v1_identity(&prelude)
                .expect("relay prelude identity");
        let response = ota_authority_protocol::ProtectedLauncherCapabilityObservationResponseV1 {
            schema_version: 1,
            message_kind:
                ota_authority_protocol::PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_RESPONSE.into(),
            request_identity: observation.identity.clone(),
            projection: binding_response.projection.clone(),
        };
        (
            observation,
            response,
            prelude,
            reservation.request,
            snapshot_response,
            binding_request,
            binding_response,
        )
    }

    fn consumption() -> ReconciledSnapshotConsumptionV1 {
        ReconciledSnapshotConsumptionV1 {
            response_identity: identity('a'),
            protected_snapshot_identity: identity('b'),
            binding_request_identity: identity('c'),
            binding_identity: identity('d'),
        }
    }

    fn consumption_links(
        reservation: &ProtectedAuthoritySnapshotReservationV1,
    ) -> SnapshotConsumptionLinksV1 {
        let snapshot = identity('b');
        let binding_request = identity('c');
        SnapshotConsumptionLinksV1 {
            response_identity: identity('a'),
            response_request_identity: reservation.request_identity.clone(),
            payload_request_identity: reservation.request_identity.clone(),
            payload_startup_continuation_identity: reservation
                .startup_continuation_identity
                .clone(),
            payload_session_identity: reservation.session_identity.clone(),
            protected_snapshot_identity: snapshot.clone(),
            binding_request_identity: binding_request.clone(),
            binding_request_startup_continuation_identity: reservation
                .startup_continuation_identity
                .clone(),
            binding_request_session_identity: reservation.session_identity.clone(),
            binding_request_protected_snapshot_identity: snapshot.clone(),
            binding_response_request_identity: binding_request.clone(),
            binding_response_protected_snapshot_identity: snapshot.clone(),
            binding_request_identity_in_binding: binding_request,
            binding_startup_continuation_identity: reservation
                .startup_continuation_identity
                .clone(),
            binding_session_identity: reservation.session_identity.clone(),
            binding_protected_snapshot_identity: snapshot,
            binding_identity: identity('d'),
        }
    }

    fn capability_projection_verifier() -> ProtectedLauncherCapabilityProjectionVerifierV1 {
        let public_key = "A".repeat(43);
        let mut verifier = ProtectedLauncherCapabilityProjectionVerifierV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER.into(),
            identity: String::new(),
            key_identity: protected_launcher_capability_projection_key_identity_v1(&public_key)
                .expect("key identity"),
            public_key,
            key_usage: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1.into(),
            signature_domain: std::str::from_utf8(
                PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1,
            )
            .expect("signature domain")
            .into(),
        };
        verifier.identity =
            protected_launcher_capability_projection_verifier_v1_identity(&verifier)
                .expect("verifier identity");
        verifier
    }

    fn binding_bundle_verifier() -> ProtectedSecretDeliveryBindingBundleVerifierV1 {
        let public_key = "A".repeat(43);
        let mut verifier = ProtectedSecretDeliveryBindingBundleVerifierV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_VERIFIER.into(),
            identity: String::new(),
            key_identity: protected_secret_delivery_binding_bundle_key_identity_v1(&public_key)
                .expect("binding key identity"),
            public_key,
            key_usage: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_KEY_USAGE_V1.into(),
            signature_domain: std::str::from_utf8(
                PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_SIGNATURE_DOMAIN_V1,
            )
            .expect("binding signature domain")
            .into(),
        };
        verifier.identity =
            protected_secret_delivery_binding_bundle_verifier_v1_identity(&verifier)
                .expect("binding verifier identity");
        verifier
    }

    fn authority_records() -> (
        ProtectedSecretDeliveryVerifierStoreV1,
        ProtectedSecretDeliveryBindingBundleV1,
    ) {
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("current time");
        let verifier = binding_bundle_verifier();
        let payload_bytes = br#"{"schema_version":1,"bindings":[]}"#;
        let mut bundle = ProtectedSecretDeliveryBindingBundleV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE.into(),
            identity: String::new(),
            authority_id: "ota-secret-delivery".into(),
            generation: 1,
            issued_at_unix_seconds: now.saturating_sub(1),
            expires_at_unix_seconds: now + 300,
            verifier_identity: verifier.identity.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload_bytes),
            payload_identity: protected_secret_delivery_binding_bundle_payload_v1_identity(
                payload_bytes,
            )
            .expect("binding payload identity"),
            signature: "A".repeat(86),
        };
        bundle.identity =
            protected_secret_delivery_binding_bundle_v1_identity(&bundle).expect("bundle identity");
        let mut store = ProtectedSecretDeliveryVerifierStoreV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_VERIFIER_STORE.into(),
            identity: String::new(),
            authority_id: bundle.authority_id.clone(),
            generation: 1,
            not_before_unix_seconds: bundle.issued_at_unix_seconds,
            not_after_unix_seconds: bundle.expires_at_unix_seconds,
            verifiers: vec![verifier],
            active_binding_bundle_identity: bundle.identity.clone(),
            active_binding_bundle_generation: bundle.generation,
        };
        store.identity =
            protected_secret_delivery_verifier_store_v1_identity(&store).expect("store identity");
        (store, bundle)
    }

    fn store_descriptor(
        role: ProtectedLauncherDescriptorRoleV1,
        seed: u64,
        bytes: &[u8],
    ) -> ProtectedLauncherDescriptorV1 {
        let mut descriptor = ProtectedLauncherDescriptorV1 {
            schema_version: 1,
            identity: String::new(),
            role,
            kind: ProtectedLauncherDescriptorKindV1::RegularFile,
            access: ProtectedLauncherDescriptorAccessV1::ReadOnly,
            device: seed,
            inode: seed + 100,
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o400,
            size: bytes.len() as u64,
            content_identity: Some(
                protected_launcher_store_content_identity_v1(role, bytes)
                    .expect("content identity"),
            ),
        };
        descriptor.identity =
            protected_launcher_descriptor_v1_identity(&descriptor).expect("descriptor identity");
        descriptor
    }

    fn protocol_records(
        startup: &LauncherStartupContinuationV1,
        request: &ProtectedAuthoritySnapshotRequestV1,
    ) -> (
        ProtectedAuthoritySnapshotResponseV1,
        ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
        ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    ) {
        let (verifier_store, binding_bundle) = authority_records();
        let verifier_bytes = serde_json::to_vec(&verifier_store).expect("verifier bytes");
        let binding_bytes = serde_json::to_vec(&binding_bundle).expect("binding bytes");
        let payload = ProtectedAuthoritySnapshotPayloadV1 {
            schema_version: 1,
            record_kind: PROTECTED_AUTHORITY_SNAPSHOT.into(),
            request_identity: request.identity.clone(),
            launcher_request_identity: request.launcher_request_identity.clone(),
            startup_continuation_identity: request.startup_continuation_identity.clone(),
            session_identity: request.session_identity.clone(),
            contract_identity: request.contract_identity.clone(),
            selected_execution_graph_identity: request.selected_execution_graph_identity.clone(),
            verifier_store_descriptor: store_descriptor(
                ProtectedLauncherDescriptorRoleV1::VerifierStore,
                11,
                &verifier_bytes,
            ),
            binding_store_descriptor: store_descriptor(
                ProtectedLauncherDescriptorRoleV1::BindingStore,
                12,
                &binding_bytes,
            ),
            verifier_store,
            binding_bundle,
            verifier_store_bytes: URL_SAFE_NO_PAD.encode(verifier_bytes),
            binding_store_bytes: URL_SAFE_NO_PAD.encode(binding_bytes),
        };
        let mut response = ProtectedAuthoritySnapshotResponseV1 {
            schema_version: 1,
            message_kind: PROTECTED_AUTHORITY_SNAPSHOT_RESPONSE.into(),
            identity: String::new(),
            request_identity: request.identity.clone(),
            protected_snapshot_identity: protected_authority_snapshot_payload_v1_identity(&payload)
                .expect("snapshot identity"),
            payload,
        };
        response.identity = protected_authority_snapshot_response_v1_identity(&response)
            .expect("response identity");

        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).expect("current time");
        let nonce = [9_u8; 32];
        let mut challenge = ProtectedLauncherCapabilityObservationChallengeV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE.into(),
            identity: String::new(),
            workflow_run_id: "34153231585".into(),
            workflow_run_attempt: "1".into(),
            workflow_reference:
                "ota-run/ota/.github/workflows/secret-delivery-oidc-endpoint-evidence.yml@refs/heads/1.6.28-implementation"
                    .into(),
            nonce_commitment: protected_launcher_capability_observation_nonce_commitment_v1(&nonce)
                .expect("observation nonce commitment"),
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now + 300,
        };
        challenge.identity =
            protected_launcher_capability_observation_challenge_v1_identity(&challenge)
                .expect("observation challenge identity");
        let mut observation = ProtectedLauncherCapabilityObservationRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST.into(),
            identity: String::new(),
            challenge: challenge.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            runner_version: "2.337.0".into(),
            expected_launcher_request_identity: request.launcher_request_identity.clone(),
        };
        observation.identity =
            protected_launcher_capability_observation_request_v1_identity(&observation)
                .expect("observation request identity");
        let mut binding_request = ProtectedLauncherSecretDeliveryTransactionBindingRequestV2 {
            schema_version: 2,
            message_kind: PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2.into(),
            identity: String::new(),
            launcher_request_identity: request.launcher_request_identity.clone(),
            observation,
            secret_transaction_candidate_identity: identity('c'),
            startup_continuation_identity: startup.identity.clone(),
            session_identity: request.session_identity.clone(),
            same_child_capability_prelude_identity: identity('f'),
            protected_snapshot_identity: response.protected_snapshot_identity.clone(),
        };
        binding_request.identity =
            protected_launcher_secret_delivery_transaction_binding_request_v2_identity(
                &binding_request,
            )
            .expect("binding request identity");
        let projection_verifier = capability_projection_verifier();
        let projection_payload = ProtectedLauncherCapabilityObservationProjectionPayloadV1 {
            schema_version: 1,
            evidence_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION.into(),
            challenge_identity: challenge.identity,
            derivation: "verified".into(),
            target: ProtectedLauncherCapabilityObservationTargetV1 {
                environment: "self_hosted".into(),
                os: "linux".into(),
                architecture: "x64".into(),
            },
            capability_class: "systemd_protected_launcher_v4".into(),
            runner_version: "2.337.0".into(),
            signing_key_identity: projection_verifier.key_identity.clone(),
        };
        let projection = ProtectedLauncherCapabilityObservationProjectionV1 {
            projection_identity: protected_launcher_capability_observation_projection_v1_identity(
                &projection_payload,
            )
            .expect("projection identity"),
            payload: projection_payload,
            signature: "A".repeat(86),
        };
        let mut binding = ProtectedLauncherSecretDeliveryTransactionBindingV2 {
            schema_version: 2,
            message_kind: PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_V2.into(),
            identity: String::new(),
            request_identity: binding_request.identity.clone(),
            launcher_request_identity: binding_request.launcher_request_identity.clone(),
            startup_continuation_identity: binding_request.startup_continuation_identity.clone(),
            session_identity: binding_request.session_identity.clone(),
            same_child_capability_prelude_identity: binding_request
                .same_child_capability_prelude_identity
                .clone(),
            protected_snapshot_identity: binding_request.protected_snapshot_identity.clone(),
            protected_capability_identity: identity('d'),
            secret_transaction_candidate_identity: binding_request
                .secret_transaction_candidate_identity
                .clone(),
            observation_request_identity: binding_request.observation.identity.clone(),
            projection_identity: projection.projection_identity.clone(),
            verifier_identity: projection_verifier.identity,
            installation_evidence_identity: identity('e'),
            expires_at_unix_seconds: binding_request
                .observation
                .challenge
                .expires_at_unix_seconds,
        };
        binding.identity =
            protected_launcher_secret_delivery_transaction_binding_v2_identity(&binding)
                .expect("binding identity");
        let binding_response = ProtectedLauncherSecretDeliveryTransactionBindingResponseV2 {
            schema_version: 2,
            message_kind: PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_RESPONSE_V2.into(),
            request_identity: binding_request.identity.clone(),
            same_child_capability_prelude_identity: binding_request
                .same_child_capability_prelude_identity
                .clone(),
            protected_snapshot_identity: binding_request.protected_snapshot_identity.clone(),
            binding,
            projection,
        };
        (response, binding_request, binding_response)
    }

    fn read_record(
        directory: &Path,
        reservation: &ProtectedAuthoritySnapshotReservationV1,
    ) -> SnapshotReplayRecordV1 {
        serde_json::from_slice(
            &fs::read(directory.join(&reservation.record_name)).expect("record bytes"),
        )
        .expect("replay record")
    }

    #[test]
    fn snapshot_replay_reservation_is_distinct_and_one_use() {
        let directory = tempdir().expect("replay directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let metadata = directory.path().metadata().expect("metadata");
        let store = ProtectedAuthoritySnapshotReplayStoreV1::open_for_test(
            directory.path(),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("replay store");
        let (startup, request) = exchange();
        store
            .reserve(&request, &startup)
            .expect("first reservation");
        assert!(matches!(
            store.reserve(&request, &startup),
            Err(ProtectedAuthoritySnapshotReplayError::ReplayDetected)
        ));
        let mut sibling = request;
        sibling.challenge.nonce_commitment = identity('8');
        sibling.challenge.identity =
            protected_authority_snapshot_challenge_v1_identity(&sibling.challenge)
                .expect("sibling challenge");
        sibling.identity =
            protected_authority_snapshot_request_v1_identity(&sibling).expect("sibling request");
        assert!(matches!(
            store.reserve(&sibling, &startup),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        ));
    }

    #[test]
    fn snapshot_replay_refusal_is_terminal_and_one_use() {
        let (directory, store, reservation, response, binding_request, binding_response) =
            protocol_replay_fixture();
        store.refuse(&reservation).expect("terminal refusal");
        assert_eq!(
            read_record(directory.path(), &reservation).status,
            SnapshotReplayStatusV1::Refused
        );
        assert_eq!(
            store.refuse(&reservation),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        );
        assert_eq!(
            store.consume(&reservation, &response, &binding_request, &binding_response),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        );
    }

    #[test]
    fn snapshot_replay_consumption_is_exact_durable_and_one_use() {
        let (directory, store, reservation, response, binding_request, binding_response) =
            protocol_replay_fixture();
        let consumption = ReconciledSnapshotConsumptionV1 {
            response_identity: response.identity.clone(),
            protected_snapshot_identity: response.protected_snapshot_identity.clone(),
            binding_request_identity: binding_request.identity.clone(),
            binding_identity: binding_response.binding.identity.clone(),
        };
        store
            .consume(&reservation, &response, &binding_request, &binding_response)
            .expect("exact consumption");
        assert_eq!(
            read_record(directory.path(), &reservation),
            SnapshotReplayRecordV1 {
                schema_version: 1,
                request_identity: reservation.request_identity.clone(),
                challenge_identity: reservation.challenge_identity.clone(),
                startup_continuation_identity: reservation.startup_continuation_identity.clone(),
                session_identity: reservation.session_identity.clone(),
                status: SnapshotReplayStatusV1::Consumed,
                response_identity: Some(consumption.response_identity.clone()),
                protected_snapshot_identity: Some(consumption.protected_snapshot_identity.clone(),),
                binding_request_identity: Some(consumption.binding_request_identity.clone()),
                binding_identity: Some(consumption.binding_identity.clone()),
            }
        );
        assert_eq!(
            store.consume(&reservation, &response, &binding_request, &binding_response,),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        );
    }

    #[test]
    fn snapshot_replay_production_consumption_refuses_protocol_substitution() {
        for case in 0..6 {
            let (
                directory,
                store,
                reservation,
                mut response,
                mut binding_request,
                mut binding_response,
            ) = protocol_replay_fixture();
            match case {
                0 => response.identity = identity('f'),
                1 => {
                    response.payload.contract_identity = identity('f');
                    response.protected_snapshot_identity =
                        protected_authority_snapshot_payload_v1_identity(&response.payload)
                            .expect("substituted snapshot identity");
                    response.identity =
                        protected_authority_snapshot_response_v1_identity(&response)
                            .expect("substituted response identity");
                }
                2 => {
                    binding_request.protected_snapshot_identity = identity('f');
                    binding_request.identity =
                        protected_launcher_secret_delivery_transaction_binding_request_v2_identity(
                            &binding_request,
                        )
                        .expect("substituted binding request identity");
                }
                3 => binding_response.request_identity = identity('f'),
                4 => {
                    binding_response.binding.protected_snapshot_identity = identity('f');
                    binding_response.binding.identity =
                        protected_launcher_secret_delivery_transaction_binding_v2_identity(
                            &binding_response.binding,
                        )
                        .expect("substituted binding identity");
                }
                5 => binding_response.binding.identity = identity('f'),
                _ => unreachable!(),
            }
            assert_eq!(
                store.consume(&reservation, &response, &binding_request, &binding_response,),
                Err(ProtectedAuthoritySnapshotReplayError::Mismatch),
                "protocol substitution case {case} must refuse",
            );
            assert_eq!(
                read_record(directory.path(), &reservation).status,
                SnapshotReplayStatusV1::Reserved,
                "protocol substitution case {case} must remain reserved",
            );
        }
    }

    #[test]
    fn snapshot_replay_consumption_refuses_exchange_link_substitution() {
        let (directory, _, reservation) = replay_fixture();
        let exact = consumption_links(&reservation);
        assert_eq!(
            reconcile_consumption_links(&reservation, &exact),
            Ok(consumption())
        );
        macro_rules! substitution_refuses {
            ($field:ident) => {{
                let mut substituted = exact.clone();
                substituted.$field = identity('e');
                assert_eq!(
                    reconcile_consumption_links(&reservation, &substituted),
                    Err(ProtectedAuthoritySnapshotReplayError::Mismatch),
                    "{} substitution must refuse",
                    stringify!($field),
                );
            }};
        }
        substitution_refuses!(response_request_identity);
        substitution_refuses!(payload_request_identity);
        substitution_refuses!(payload_startup_continuation_identity);
        substitution_refuses!(payload_session_identity);
        substitution_refuses!(binding_request_startup_continuation_identity);
        substitution_refuses!(binding_request_session_identity);
        substitution_refuses!(binding_request_protected_snapshot_identity);
        substitution_refuses!(binding_response_request_identity);
        substitution_refuses!(binding_response_protected_snapshot_identity);
        substitution_refuses!(binding_request_identity_in_binding);
        substitution_refuses!(binding_startup_continuation_identity);
        substitution_refuses!(binding_session_identity);
        substitution_refuses!(binding_protected_snapshot_identity);
        assert_eq!(
            read_record(directory.path(), &reservation).status,
            SnapshotReplayStatusV1::Reserved
        );
    }

    #[test]
    fn snapshot_replay_consumption_refuses_replaced_or_unprotected_records() {
        for mutation in ["malformed", "mode", "symlink"] {
            let (directory, store, reservation) = replay_fixture();
            let record = directory.path().join(&reservation.record_name);
            match mutation {
                "malformed" => fs::write(&record, b"not-json").expect("malformed record"),
                "mode" => fs::set_permissions(&record, fs::Permissions::from_mode(0o640))
                    .expect("record mode"),
                "symlink" => {
                    fs::remove_file(&record).expect("remove record");
                    let target = directory.path().join("replacement.json");
                    fs::write(&target, b"{}").expect("replacement");
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                        .expect("replacement mode");
                    symlink(&target, &record).expect("replacement symlink");
                }
                _ => unreachable!(),
            }
            assert_eq!(
                store.consume_reconciled(&reservation, &consumption()),
                Err(ProtectedAuthoritySnapshotReplayError::Unavailable)
            );
        }
    }

    #[test]
    fn snapshot_replay_failed_consumption_preserves_reservation() {
        let (directory, store, reservation) = replay_fixture();
        let mut record = read_record(directory.path(), &reservation);
        record.response_identity = Some(identity('e'));
        fs::write(
            directory.path().join(&reservation.record_name),
            serde_jcs::to_vec(&record).expect("record bytes"),
        )
        .expect("substituted record");
        assert_eq!(
            store.consume_reconciled(&reservation, &consumption()),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        );
        assert_eq!(
            read_record(directory.path(), &reservation).status,
            SnapshotReplayStatusV1::Reserved
        );
    }

    #[test]
    #[ignore = "requires the fixed root-owned production replay directory"]
    fn production_snapshot_replay_store_opens_the_verified_protected_path() {
        let store = ProtectedAuthoritySnapshotReplayStoreV1::open().expect("production replay");
        let (startup, request) = exchange();
        let reservation = store.reserve(&request, &startup).expect("reservation");
        let (response, binding_request, binding_response) = protocol_records(&startup, &request);
        assert!(matches!(
            store.reserve(&request, &startup),
            Err(ProtectedAuthoritySnapshotReplayError::ReplayDetected)
        ));
        store
            .consume(&reservation, &response, &binding_request, &binding_response)
            .expect("production replay consumption");
        assert_eq!(
            store.consume(&reservation, &response, &binding_request, &binding_response,),
            Err(ProtectedAuthoritySnapshotReplayError::Mismatch)
        );

        assert_eq!(unsafe { libc::geteuid() }, 0, "test requires root");
        let record = Path::new(AUTHORITY_SNAPSHOT_REPLAY_DIRECTORY).join(&reservation.record_name);
        let record = CString::new(record.as_os_str().as_bytes()).expect("record path");
        assert_eq!(unsafe { libc::chown(record.as_ptr(), 1, 0) }, 0);
        assert_eq!(
            store.consume_reconciled(&reservation, &consumption()),
            Err(ProtectedAuthoritySnapshotReplayError::Unavailable)
        );
    }
}
