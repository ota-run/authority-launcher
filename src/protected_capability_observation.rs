//! Root-owned issuance of a public observation projection for one protected capability.
//!
//! The protected Launcher service owns capability derivation and delegates only projection signing
//! to the separate Attestor. Core receives only the resulting public projection over the fixed
//! local service boundary; provider operations remain outside this route.

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ota_authority_protocol::{
    ProtectedLauncherCapabilityObservationChallengeV1,
    ProtectedLauncherCapabilityObservationProjectionPayloadV1,
    ProtectedLauncherCapabilityObservationRequestV1,
    ProtectedLauncherCapabilityObservationResponseV1,
    ProtectedLauncherCapabilityObservationSigningRequestV1,
    ProtectedLauncherCapabilityObservationSigningResponseV1,
    ProtectedLauncherCapabilityObservationTargetV1,
    ProtectedLauncherCapabilityProjectionVerifierV1, launcher_invocation_request_identity,
    protected_launcher_capability_observation_challenge_v1_identity,
    protected_launcher_capability_observation_nonce_commitment_v1,
    protected_launcher_capability_observation_projection_v1_identity,
    protected_launcher_capability_observation_request_v1_identity,
    protected_launcher_capability_observation_signing_request_v1_identity,
    reconcile_protected_launcher_capability_observation_signing_response_v1,
    validate_protected_launcher_capability_observation_challenge_v1,
    validate_protected_launcher_capability_observation_projection_v1,
    validate_protected_launcher_capability_observation_response_v1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::attestation_client::{load_producer_binding, request_capability_observation_signature};
use crate::installation_manifest::{
    CAPABILITY_OBSERVATION_REPLAY_DIRECTORY, load_capability_projection_verifier,
};
use crate::protected_launcher_capability::{
    ProtectedLauncherCapabilityContextV1, ProtectedLauncherCapabilityError,
    RetainedProtectedLauncherObservationV1, derive_protected_launcher_capability_v1,
    open_protected_directory_chain, open_root, openat2_beneath, openat2_beneath_with_mode,
};

#[derive(Debug, Error)]
pub(crate) enum ProtectedCapabilityObservationError {
    #[error("protected capability observation challenge is invalid")]
    InvalidChallenge,
    #[error("protected capability observation replay state is unavailable or uncertain")]
    ReplayStateUnavailable,
    #[error("protected capability observation challenge has already been used")]
    ReplayDetected,
    #[error("protected capability derivation failed")]
    Capability(#[from] ProtectedLauncherCapabilityError),
    #[error("protected capability observation projection is invalid")]
    ProjectionInvalid,
    #[error("protected capability observation signer authority is unavailable or mismatched")]
    SignerAuthorityUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReplayRecordV1 {
    schema_version: u32,
    challenge: ProtectedLauncherCapabilityObservationChallengeV1,
    status: ReplayStatusV1,
    protected_capability_identity: Option<String>,
    projection_identity: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReplayStatusV1 {
    Reserved,
    Consumed,
}

pub(crate) struct ProtectedCapabilityObservationReplayStoreV1 {
    directory: File,
    expected_uid: u32,
}

impl ProtectedCapabilityObservationReplayStoreV1 {
    pub(crate) fn open() -> Result<Self, ProtectedCapabilityObservationError> {
        let directory = Path::new(CAPABILITY_OBSERVATION_REPLAY_DIRECTORY);
        let relative = directory
            .strip_prefix("/")
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        let root = open_root(Path::new("/"), 0, 0)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        let directory = open_protected_directory_chain(root.as_raw_fd(), relative, 0, 0, true)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        Self::from_directory(directory.as_raw_fd(), 0)
    }

    fn from_directory(
        directory: std::os::fd::RawFd,
        expected_uid: u32,
    ) -> Result<Self, ProtectedCapabilityObservationError> {
        let directory = openat2_beneath(
            directory,
            b".",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        Ok(Self {
            directory: File::from(directory),
            expected_uid,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, ProtectedCapabilityObservationError> {
        let directory = open_root(directory, expected_uid, expected_gid)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        Self::from_directory(directory.as_raw_fd(), expected_uid)
    }

    fn reserve(
        &self,
        challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
        nonce: &[u8],
        observed_at_unix_seconds: u64,
    ) -> Result<String, ProtectedCapabilityObservationError> {
        validate_challenge(challenge, nonce, observed_at_unix_seconds)?;
        let lock = self.lock()?;
        let _guard = FileLockGuard(&lock);
        let name = self.record_name(challenge)?;
        let record = ReplayRecordV1 {
            schema_version: 1,
            challenge: challenge.clone(),
            status: ReplayStatusV1::Reserved,
            protected_capability_identity: None,
            projection_identity: None,
        };
        write_new_record(self.directory.as_raw_fd(), &name, &record)?;
        sync_directory(&self.directory)?;
        Ok(name)
    }

    fn consume(
        &self,
        name: &str,
        challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
        protected_capability_identity: &str,
        projection_identity: &str,
    ) -> Result<(), ProtectedCapabilityObservationError> {
        let lock = self.lock()?;
        let _guard = FileLockGuard(&lock);
        let mut file = File::from(
            openat2_beneath(
                self.directory.as_raw_fd(),
                name.as_bytes(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?,
        );
        verify_protected_file(&file, self.expected_uid, 0o600)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        let mut record: ReplayRecordV1 = serde_json::from_slice(&bytes)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        if record.schema_version != 1
            || record.status != ReplayStatusV1::Reserved
            || record.challenge != *challenge
            || record.protected_capability_identity.is_some()
            || record.projection_identity.is_some()
        {
            return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
        }
        record.status = ReplayStatusV1::Consumed;
        record.protected_capability_identity = Some(protected_capability_identity.into());
        record.projection_identity = Some(projection_identity.into());
        replace_record(self.directory.as_raw_fd(), name, &record)?;
        sync_directory(&self.directory)
    }

    fn lock(&self) -> Result<File, ProtectedCapabilityObservationError> {
        let file = File::from(
            openat2_beneath_with_mode(
                self.directory.as_raw_fd(),
                b"replay.lock",
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?,
        );
        verify_protected_file(&file, self.expected_uid, 0o600)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
        }
        Ok(file)
    }

    fn record_name(
        &self,
        challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
    ) -> Result<String, ProtectedCapabilityObservationError> {
        let identity = challenge
            .identity
            .strip_prefix("sha256:")
            .ok_or(ProtectedCapabilityObservationError::InvalidChallenge)?;
        Ok(format!("{identity}.json"))
    }
}

struct FileLockGuard<'a>(&'a File);

impl Drop for FileLockGuard<'_> {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_and_sign_capability_observation_v1(
    replay: &ProtectedCapabilityObservationReplayStoreV1,
    request: &ProtectedLauncherCapabilityObservationRequestV1,
    context: &ProtectedLauncherCapabilityContextV1<'_>,
    observation: &mut RetainedProtectedLauncherObservationV1,
) -> Result<ProtectedLauncherCapabilityObservationResponseV1, ProtectedCapabilityObservationError> {
    let observed_at_unix_seconds = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?;
    let verifier = load_capability_projection_verifier()
        .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
    let binding = load_producer_binding()
        .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
    derive_and_sign_capability_observation_at_v1(
        replay,
        request,
        observed_at_unix_seconds,
        &binding,
        &verifier,
        context,
        observation,
        |binding, verifier, request| {
            request_capability_observation_signature(binding, verifier, request)
                .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_and_sign_capability_observation_at_v1<F>(
    replay: &ProtectedCapabilityObservationReplayStoreV1,
    request: &ProtectedLauncherCapabilityObservationRequestV1,
    observed_at_unix_seconds: u64,
    binding: &ota_authority_protocol::LauncherAttestationProducerBindingV1,
    verifier: &ProtectedLauncherCapabilityProjectionVerifierV1,
    context: &ProtectedLauncherCapabilityContextV1<'_>,
    observation: &mut RetainedProtectedLauncherObservationV1,
    sign: F,
) -> Result<ProtectedLauncherCapabilityObservationResponseV1, ProtectedCapabilityObservationError>
where
    F: FnOnce(
        &ota_authority_protocol::LauncherAttestationProducerBindingV1,
        &ProtectedLauncherCapabilityProjectionVerifierV1,
        &ProtectedLauncherCapabilityObservationSigningRequestV1,
    ) -> Result<
        ProtectedLauncherCapabilityObservationSigningResponseV1,
        ProtectedCapabilityObservationError,
    >,
{
    let observed_launcher_request_identity = launcher_invocation_request_identity(context.request)
        .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?;
    if request.expected_launcher_request_identity != observed_launcher_request_identity {
        return Err(ProtectedCapabilityObservationError::InvalidChallenge);
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&request.nonce)
        .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?;
    let request_identity = protected_launcher_capability_observation_request_v1_identity(request)
        .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?;
    if request.identity != request_identity {
        return Err(ProtectedCapabilityObservationError::InvalidChallenge);
    }
    let record_path = replay.reserve(&request.challenge, &nonce, observed_at_unix_seconds)?;
    let capability = derive_protected_launcher_capability_v1(context, observation)?;
    let payload = ProtectedLauncherCapabilityObservationProjectionPayloadV1 {
        schema_version: 1,
        evidence_kind: ota_authority_protocol::PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION.into(),
        challenge_identity: request.challenge.identity.clone(),
        derivation: "verified".into(),
        target: ProtectedLauncherCapabilityObservationTargetV1 {
            environment: "self_hosted".into(),
            os: "linux".into(),
            architecture: "x64".into(),
        },
        capability_class: "systemd_protected_launcher_v4".into(),
        runner_version: request.runner_version.clone(),
        signing_key_identity: verifier.key_identity.clone(),
    };
    let projection_identity =
        protected_launcher_capability_observation_projection_v1_identity(&payload)
            .map_err(|_| ProtectedCapabilityObservationError::ProjectionInvalid)?;
    let mut signing_request = ProtectedLauncherCapabilityObservationSigningRequestV1 {
        schema_version: 1,
        message_kind:
            ota_authority_protocol::PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNING_REQUEST.into(),
        identity: String::new(),
        producer_binding_identity: binding.identity.clone(),
        verifier_identity: verifier.identity.clone(),
        protected_capability_identity: capability.identity.clone(),
        payload,
        projection_identity: projection_identity.clone(),
    };
    signing_request.identity =
        protected_launcher_capability_observation_signing_request_v1_identity(&signing_request)
            .map_err(|_| ProtectedCapabilityObservationError::ProjectionInvalid)?;
    let signing_response = sign(binding, verifier, &signing_request)?;
    reconcile_protected_launcher_capability_observation_signing_response_v1(
        &signing_request,
        &signing_response,
    )
    .map_err(|_| ProtectedCapabilityObservationError::ProjectionInvalid)?;
    let projection = signing_response.projection;
    validate_protected_launcher_capability_observation_projection_v1(&projection)
        .map_err(|_| ProtectedCapabilityObservationError::ProjectionInvalid)?;
    replay.consume(
        &record_path,
        &request.challenge,
        &capability.identity,
        &projection_identity,
    )?;
    let response = ProtectedLauncherCapabilityObservationResponseV1 {
        schema_version: 1,
        message_kind: ota_authority_protocol::PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_RESPONSE
            .into(),
        request_identity,
        projection,
    };
    validate_protected_launcher_capability_observation_response_v1(&response)
        .map_err(|_| ProtectedCapabilityObservationError::ProjectionInvalid)?;
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_and_sign_capability_observation_for_test_v1(
    replay: &ProtectedCapabilityObservationReplayStoreV1,
    request: &ProtectedLauncherCapabilityObservationRequestV1,
    observed_at_unix_seconds: u64,
    binding: &ota_authority_protocol::LauncherAttestationProducerBindingV1,
    verifier: &ProtectedLauncherCapabilityProjectionVerifierV1,
    context: &ProtectedLauncherCapabilityContextV1<'_>,
    observation: &mut RetainedProtectedLauncherObservationV1,
    sign: impl FnOnce(
        &ota_authority_protocol::LauncherAttestationProducerBindingV1,
        &ProtectedLauncherCapabilityProjectionVerifierV1,
        &ProtectedLauncherCapabilityObservationSigningRequestV1,
    ) -> Result<
        ProtectedLauncherCapabilityObservationSigningResponseV1,
        ProtectedCapabilityObservationError,
    >,
) -> Result<ProtectedLauncherCapabilityObservationResponseV1, ProtectedCapabilityObservationError> {
    derive_and_sign_capability_observation_at_v1(
        replay,
        request,
        observed_at_unix_seconds,
        binding,
        verifier,
        context,
        observation,
        sign,
    )
}

fn validate_challenge(
    challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
    nonce: &[u8],
    observed_at_unix_seconds: u64,
) -> Result<(), ProtectedCapabilityObservationError> {
    if protected_launcher_capability_observation_challenge_v1_identity(challenge)
        .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?
        != challenge.identity
        || protected_launcher_capability_observation_nonce_commitment_v1(nonce)
            .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)?
            != challenge.nonce_commitment
    {
        return Err(ProtectedCapabilityObservationError::InvalidChallenge);
    }
    validate_protected_launcher_capability_observation_challenge_v1(
        challenge,
        observed_at_unix_seconds,
    )
    .map_err(|_| ProtectedCapabilityObservationError::InvalidChallenge)
}

fn verify_protected_directory(
    directory: &Path,
    expected_uid: u32,
) -> Result<(), ProtectedCapabilityObservationError> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o700
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
    }
    let mut current = directory.parent();
    while let Some(parent) = current {
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
        if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
            return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
        }
        current = parent.parent();
    }
    Ok(())
}

fn verify_protected_file(
    file: &File,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<(), ProtectedCapabilityObservationError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
    }
    Ok(())
}

fn write_new_record(
    directory: std::os::fd::RawFd,
    name: &str,
    record: &ReplayRecordV1,
) -> Result<(), ProtectedCapabilityObservationError> {
    let bytes = serde_jcs::to_vec(record)
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    let mut file = File::from(
        openat2_beneath_with_mode(
            directory,
            name.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|_| ProtectedCapabilityObservationError::ReplayDetected)?,
    );
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)
}

fn replace_record(
    directory: std::os::fd::RawFd,
    name: &str,
    record: &ReplayRecordV1,
) -> Result<(), ProtectedCapabilityObservationError> {
    let bytes = serde_jcs::to_vec(record)
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    let temporary = format!(".{name}.{}.tmp", std::process::id());
    let mut file = File::from(
        openat2_beneath_with_mode(
            directory,
            temporary.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?,
    );
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    let temporary = CString::new(temporary)
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    let name = CString::new(name)
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)?;
    if unsafe { libc::renameat(directory, temporary.as_ptr(), directory, name.as_ptr()) } != 0 {
        return Err(ProtectedCapabilityObservationError::ReplayStateUnavailable);
    }
    Ok(())
}

fn sync_directory(directory: &File) -> Result<(), ProtectedCapabilityObservationError> {
    directory
        .sync_all()
        .map_err(|_| ProtectedCapabilityObservationError::ReplayStateUnavailable)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    fn challenge(nonce: &[u8]) -> ProtectedLauncherCapabilityObservationChallengeV1 {
        let mut challenge = ProtectedLauncherCapabilityObservationChallengeV1 {
            schema_version: 1,
            message_kind: ota_authority_protocol::PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE.into(),
            identity: String::new(),
            workflow_run_id: "34153231585".into(),
            workflow_run_attempt: "1".into(),
            workflow_reference: "ota-run/ota/.github/workflows/secret-delivery-oidc-endpoint-evidence.yml@refs/heads/1.6.28-implementation".into(),
            nonce_commitment: protected_launcher_capability_observation_nonce_commitment_v1(nonce)
                .expect("nonce commitment"),
            issued_at_unix_seconds: 1_788_800_000,
            expires_at_unix_seconds: 1_788_800_300,
        };
        challenge.identity =
            protected_launcher_capability_observation_challenge_v1_identity(&challenge)
                .expect("challenge identity");
        challenge
    }

    #[test]
    fn replay_store_reserves_once_and_consumes_exact_challenge() {
        let directory = tempdir().expect("replay directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let expected_uid = directory.path().metadata().expect("metadata").uid();
        let expected_gid = directory.path().metadata().expect("metadata").gid();
        let store = ProtectedCapabilityObservationReplayStoreV1::open_for_test(
            directory.path(),
            expected_uid,
            expected_gid,
        )
        .expect("replay store");
        let nonce = [7_u8; 32];
        let challenge = challenge(&nonce);
        let record_path = store
            .reserve(&challenge, &nonce, challenge.issued_at_unix_seconds)
            .expect("reserve challenge");
        assert!(matches!(
            store.reserve(&challenge, &nonce, challenge.issued_at_unix_seconds),
            Err(ProtectedCapabilityObservationError::ReplayDetected)
        ));
        store
            .consume(
                &record_path,
                &challenge,
                &format!("sha256:{}", "a".repeat(64)),
                &format!("sha256:{}", "b".repeat(64)),
            )
            .expect("consume challenge");
        assert!(matches!(
            store.consume(
                &record_path,
                &challenge,
                &format!("sha256:{}", "a".repeat(64)),
                &format!("sha256:{}", "b".repeat(64)),
            ),
            Err(ProtectedCapabilityObservationError::ReplayStateUnavailable)
        ));
    }

    #[test]
    fn replay_store_refuses_nonce_and_challenge_substitution() {
        let directory = tempdir().expect("replay directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let expected_uid = directory.path().metadata().expect("metadata").uid();
        let expected_gid = directory.path().metadata().expect("metadata").gid();
        let store = ProtectedCapabilityObservationReplayStoreV1::open_for_test(
            directory.path(),
            expected_uid,
            expected_gid,
        )
        .expect("replay store");
        let nonce = [7_u8; 32];
        let challenge = challenge(&nonce);
        assert!(matches!(
            store.reserve(&challenge, &[8_u8; 32], challenge.issued_at_unix_seconds),
            Err(ProtectedCapabilityObservationError::InvalidChallenge)
        ));
        let mut substituted = challenge.clone();
        substituted.workflow_run_attempt = "2".into();
        assert!(matches!(
            store.reserve(&substituted, &nonce, challenge.issued_at_unix_seconds),
            Err(ProtectedCapabilityObservationError::InvalidChallenge)
        ));
    }

    #[test]
    fn replay_store_uses_the_retained_directory_after_path_replacement() {
        let parent = tempdir().expect("replay parent");
        let original = parent.path().join("replay");
        let retained = parent.path().join("retained");
        fs::create_dir(&original).expect("replay directory");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let metadata = original.metadata().expect("metadata");
        let store = ProtectedCapabilityObservationReplayStoreV1::open_for_test(
            &original,
            metadata.uid(),
            metadata.gid(),
        )
        .expect("retained replay store");
        fs::rename(&original, &retained).expect("move retained directory");
        fs::create_dir(&original).expect("replacement directory");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        let nonce = [9_u8; 32];
        let challenge = challenge(&nonce);
        let record_name = store
            .reserve(
                &nonce_challenge(&challenge, "2"),
                &nonce,
                challenge.issued_at_unix_seconds,
            )
            .expect("reserve through retained descriptor");
        assert!(retained.join(&record_name).is_file());
        assert!(!original.join(&record_name).exists());
    }

    fn nonce_challenge(
        challenge: &ProtectedLauncherCapabilityObservationChallengeV1,
        attempt: &str,
    ) -> ProtectedLauncherCapabilityObservationChallengeV1 {
        let mut challenge = challenge.clone();
        challenge.workflow_run_attempt = attempt.into();
        challenge.identity =
            protected_launcher_capability_observation_challenge_v1_identity(&challenge)
                .expect("challenge identity");
        challenge
    }
}
