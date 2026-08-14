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

//! Durable state retained after active-slot removal until portable archive evidence is persisted.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ota_authority_protocol::{
    LauncherExecutionFinalizationV1, LauncherFinalizationArchivePersistenceV1,
    LauncherFinalizationArchiveRequestV1, LauncherFinalizationArchiveSidecarV1,
    LauncherTerminalFrameV1, LauncherTerminalPersistenceV1, LauncherWorkingDirectoryV1,
    SignedLauncherExecutionFinalizationV1, launcher_execution_finalization_v1_identity,
    launcher_finalization_archive_persistence_v1_identity,
    launcher_finalization_archive_request_v1_identity,
    launcher_finalization_archive_sidecar_v1_identity, launcher_terminal_frame_v1_identity,
    launcher_terminal_persistence_v1_identity, launcher_working_directory_identity,
    message_identity, signed_launcher_execution_finalization_v1_identity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const FINALIZATION_JOURNAL_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.finalization-journal.v1\0";
const MAX_JOURNAL_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FinalizationJournalStageV1 {
    Intent,
    SignedFinalization,
    ArchiveRequested,
    SidecarIssued,
    SidecarAcknowledged,
    TerminalIssued,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizationJournalV1 {
    pub schema_version: u32,
    pub identity: String,
    pub stage: FinalizationJournalStageV1,
    pub invocation_id: String,
    pub principal_mapping_identity: String,
    pub launcher_request_identity: String,
    pub working_directory: LauncherWorkingDirectoryV1,
    pub finalization: LauncherExecutionFinalizationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_finalization: Option<SignedLauncherExecutionFinalizationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_request: Option<LauncherFinalizationArchiveRequestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<LauncherFinalizationArchiveSidecarV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_persistence: Option<LauncherFinalizationArchivePersistenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<LauncherTerminalFrameV1>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum FinalizationJournalError {
    #[error("the protected finalization store is unavailable")]
    StoreUnavailable,
    #[error("the protected finalization journal is invalid")]
    InvalidJournal,
    #[error("the protected finalization journal could not be persisted")]
    PersistenceFailed,
    #[error("the principal already has retained finalization state")]
    AlreadyPending,
}

pub(crate) struct FinalizationJournal {
    directory: PathBuf,
    path: PathBuf,
    journal: FinalizationJournalV1,
}

impl FinalizationJournal {
    pub(crate) fn begin(
        directory: &Path,
        expected_owner_uid: u32,
        principal_mapping_identity: &str,
        launcher_request_identity: &str,
        working_directory: LauncherWorkingDirectoryV1,
        finalization: LauncherExecutionFinalizationV1,
    ) -> Result<Self, FinalizationJournalError> {
        verify_store(directory, expected_owner_uid)?;
        let path = journal_path(directory, principal_mapping_identity)?;
        let mut journal = FinalizationJournalV1 {
            schema_version: 1,
            identity: String::new(),
            stage: FinalizationJournalStageV1::Intent,
            invocation_id: finalization.completion.invocation_id.clone(),
            principal_mapping_identity: principal_mapping_identity.into(),
            launcher_request_identity: launcher_request_identity.into(),
            working_directory,
            finalization,
            signed_finalization: None,
            archive_request: None,
            sidecar: None,
            sidecar_persistence: None,
            terminal: None,
        };
        journal.identity = finalization_journal_identity(&journal)?;
        write_new(&path, &journal).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                FinalizationJournalError::AlreadyPending
            } else {
                FinalizationJournalError::PersistenceFailed
            }
        })?;
        sync_directory(directory)?;
        Ok(Self {
            directory: directory.into(),
            path,
            journal,
        })
    }

    pub(crate) fn load_for_principal(
        directory: &Path,
        expected_owner_uid: u32,
        principal_mapping_identity: &str,
    ) -> Result<Option<Self>, FinalizationJournalError> {
        verify_store(directory, expected_owner_uid)?;
        let path = journal_path(directory, principal_mapping_identity)?;
        if !path.exists() {
            return Ok(None);
        }
        verify_file(&path, expected_owner_uid)?;
        let bytes = fs::read(&path).map_err(|_| FinalizationJournalError::StoreUnavailable)?;
        let journal: FinalizationJournalV1 =
            serde_json::from_slice(&bytes).map_err(|_| FinalizationJournalError::InvalidJournal)?;
        if finalization_journal_identity(&journal)? != journal.identity
            || journal.principal_mapping_identity != principal_mapping_identity
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        Ok(Some(Self {
            directory: directory.into(),
            path,
            journal,
        }))
    }

    pub(crate) fn record_signed_finalization(
        &mut self,
        signed: SignedLauncherExecutionFinalizationV1,
    ) -> Result<(), FinalizationJournalError> {
        if self.journal.stage != FinalizationJournalStageV1::Intent
            || signed_launcher_execution_finalization_v1_identity(&signed)
                .ok()
                .as_deref()
                != Some(signed.identity.as_str())
            || signed.finalization != self.journal.finalization
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        self.journal.stage = FinalizationJournalStageV1::SignedFinalization;
        self.journal.signed_finalization = Some(signed);
        self.persist()
    }

    pub(crate) fn record_archive_request(
        &mut self,
        request: LauncherFinalizationArchiveRequestV1,
    ) -> Result<(), FinalizationJournalError> {
        let signed = self
            .journal
            .signed_finalization
            .as_ref()
            .ok_or(FinalizationJournalError::InvalidJournal)?;
        if self.journal.stage != FinalizationJournalStageV1::SignedFinalization
            || launcher_finalization_archive_request_v1_identity(&request)
                .ok()
                .as_deref()
                != Some(request.request_identity.as_str())
            || request.launcher_request_identity != self.journal.launcher_request_identity
            || request.crossing_transaction_identity
                != self
                    .journal
                    .finalization
                    .completion
                    .crossing_transaction_identity
            || self
                .journal
                .finalization
                .completion
                .receipt_archive_identity
                .as_deref()
                != Some(request.receipt_archive_identity.as_str())
            || request
                .signed_finalization_identity
                .as_deref()
                .is_some_and(|identity| identity != signed.identity)
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        self.journal.stage = FinalizationJournalStageV1::ArchiveRequested;
        self.journal.archive_request = Some(request);
        self.persist()
    }

    pub(crate) fn record_sidecar(
        &mut self,
        sidecar: LauncherFinalizationArchiveSidecarV1,
    ) -> Result<(), FinalizationJournalError> {
        let request = self
            .journal
            .archive_request
            .as_ref()
            .ok_or(FinalizationJournalError::InvalidJournal)?;
        if self.journal.stage != FinalizationJournalStageV1::ArchiveRequested
            || launcher_finalization_archive_sidecar_v1_identity(&sidecar)
                .ok()
                .as_deref()
                != Some(sidecar.identity.as_str())
            || sidecar.signed_archive.receipt_archive_identity != request.receipt_archive_identity
            || sidecar.signed_archive.crossing_transaction_identity
                != request.crossing_transaction_identity
            || self.journal.signed_finalization.as_ref() != Some(&sidecar.signed_finalization)
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        self.journal.stage = FinalizationJournalStageV1::SidecarIssued;
        self.journal.sidecar = Some(sidecar);
        self.persist()
    }

    pub(crate) fn record_sidecar_persistence(
        &mut self,
        persistence: LauncherFinalizationArchivePersistenceV1,
    ) -> Result<(), FinalizationJournalError> {
        if self.journal.stage != FinalizationJournalStageV1::SidecarIssued
            || launcher_finalization_archive_persistence_v1_identity(&persistence)
                .ok()
                .as_deref()
                != Some(persistence.identity.as_str())
            || self
                .journal
                .archive_request
                .as_ref()
                .is_none_or(|request| request.request_identity != persistence.request_identity)
            || self
                .journal
                .sidecar
                .as_ref()
                .is_none_or(|sidecar| sidecar.identity != persistence.sidecar_identity)
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        self.journal.stage = FinalizationJournalStageV1::SidecarAcknowledged;
        self.journal.sidecar_persistence = Some(persistence);
        self.persist()
    }

    pub(crate) fn record_terminal(
        &mut self,
        terminal: LauncherTerminalFrameV1,
    ) -> Result<(), FinalizationJournalError> {
        if self.journal.stage != FinalizationJournalStageV1::SidecarAcknowledged
            || launcher_terminal_frame_v1_identity(&terminal).is_err()
            || terminal.invocation_id != self.journal.invocation_id
            || terminal.finalization.as_ref() != Some(&self.journal.finalization)
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        self.journal.stage = FinalizationJournalStageV1::TerminalIssued;
        self.journal.terminal = Some(terminal);
        self.persist()
    }

    pub(crate) fn acknowledge_terminal_and_finalize(
        &mut self,
        persistence: &LauncherTerminalPersistenceV1,
    ) -> Result<(), FinalizationJournalError> {
        let terminal = self
            .journal
            .terminal
            .as_ref()
            .ok_or(FinalizationJournalError::InvalidJournal)?;
        if self.journal.stage != FinalizationJournalStageV1::TerminalIssued
            || launcher_terminal_persistence_v1_identity(persistence)
                .ok()
                .as_deref()
                != Some(persistence.identity.as_str())
            || persistence.invocation_id != self.journal.invocation_id
            || launcher_terminal_frame_v1_identity(terminal)
                .ok()
                .as_deref()
                != Some(persistence.terminal_identity.as_str())
        {
            return Err(FinalizationJournalError::InvalidJournal);
        }
        fs::remove_file(&self.path).map_err(|_| FinalizationJournalError::PersistenceFailed)?;
        sync_directory(&self.directory)
    }

    pub(crate) fn journal(&self) -> &FinalizationJournalV1 {
        &self.journal
    }

    fn persist(&mut self) -> Result<(), FinalizationJournalError> {
        self.journal.identity = finalization_journal_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }
}

pub(crate) fn finalization_journal_identity(
    journal: &FinalizationJournalV1,
) -> Result<String, FinalizationJournalError> {
    if journal.schema_version != 1
        || !journal.invocation_id.starts_with("invocation-")
        || !journal.principal_mapping_identity.starts_with("sha256:")
        || !journal.launcher_request_identity.starts_with("sha256:")
        || launcher_working_directory_identity(&journal.working_directory)
            .ok()
            .as_deref()
            != Some(journal.working_directory.identity.as_str())
        || launcher_execution_finalization_v1_identity(&journal.finalization)
            .ok()
            .as_deref()
            != Some(journal.finalization.identity.as_str())
        || journal.invocation_id != journal.finalization.completion.invocation_id
        || !stage_is_valid(journal)
    {
        return Err(FinalizationJournalError::InvalidJournal);
    }
    let mut canonical = journal.clone();
    canonical.identity.clear();
    message_identity(FINALIZATION_JOURNAL_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| FinalizationJournalError::InvalidJournal)
}

fn stage_is_valid(journal: &FinalizationJournalV1) -> bool {
    let signed_valid = journal.signed_finalization.as_ref().is_some_and(|signed| {
        signed_launcher_execution_finalization_v1_identity(signed)
            .ok()
            .as_deref()
            == Some(signed.identity.as_str())
            && signed.finalization == journal.finalization
    });
    let request_valid = journal.archive_request.as_ref().is_some_and(|request| {
        launcher_finalization_archive_request_v1_identity(request)
            .ok()
            .as_deref()
            == Some(request.request_identity.as_str())
            && request.launcher_request_identity == journal.launcher_request_identity
            && request.crossing_transaction_identity
                == journal
                    .finalization
                    .completion
                    .crossing_transaction_identity
            && journal
                .finalization
                .completion
                .receipt_archive_identity
                .as_deref()
                == Some(request.receipt_archive_identity.as_str())
            && request
                .signed_finalization_identity
                .as_deref()
                .is_none_or(|identity| {
                    Some(identity)
                        == journal
                            .signed_finalization
                            .as_ref()
                            .map(|signed| signed.identity.as_str())
                })
    });
    let sidecar_valid = journal.sidecar.as_ref().is_some_and(|sidecar| {
        launcher_finalization_archive_sidecar_v1_identity(sidecar)
            .ok()
            .as_deref()
            == Some(sidecar.identity.as_str())
            && journal.signed_finalization.as_ref() == Some(&sidecar.signed_finalization)
            && journal.archive_request.as_ref().is_some_and(|request| {
                sidecar.signed_archive.receipt_archive_identity == request.receipt_archive_identity
                    && sidecar.signed_archive.crossing_transaction_identity
                        == request.crossing_transaction_identity
            })
    });
    let sidecar_persistence_valid =
        journal
            .sidecar_persistence
            .as_ref()
            .is_some_and(|persistence| {
                launcher_finalization_archive_persistence_v1_identity(persistence)
                    .ok()
                    .as_deref()
                    == Some(persistence.identity.as_str())
                    && journal.archive_request.as_ref().is_some_and(|request| {
                        request.request_identity == persistence.request_identity
                    })
                    && journal
                        .sidecar
                        .as_ref()
                        .is_some_and(|sidecar| sidecar.identity == persistence.sidecar_identity)
            });
    let terminal_valid = journal.terminal.as_ref().is_some_and(|terminal| {
        launcher_terminal_frame_v1_identity(terminal).is_ok()
            && terminal.invocation_id == journal.invocation_id
            && terminal.finalization.as_ref() == Some(&journal.finalization)
    });
    match journal.stage {
        FinalizationJournalStageV1::Intent => {
            journal.signed_finalization.is_none()
                && journal.archive_request.is_none()
                && journal.sidecar.is_none()
                && journal.sidecar_persistence.is_none()
                && journal.terminal.is_none()
        }
        FinalizationJournalStageV1::SignedFinalization => {
            signed_valid
                && journal.archive_request.is_none()
                && journal.sidecar.is_none()
                && journal.sidecar_persistence.is_none()
                && journal.terminal.is_none()
        }
        FinalizationJournalStageV1::ArchiveRequested => {
            signed_valid
                && request_valid
                && journal.sidecar.is_none()
                && journal.sidecar_persistence.is_none()
                && journal.terminal.is_none()
        }
        FinalizationJournalStageV1::SidecarIssued => {
            signed_valid
                && request_valid
                && sidecar_valid
                && journal.sidecar_persistence.is_none()
                && journal.terminal.is_none()
        }
        FinalizationJournalStageV1::SidecarAcknowledged => {
            signed_valid
                && request_valid
                && sidecar_valid
                && sidecar_persistence_valid
                && journal.terminal.is_none()
        }
        FinalizationJournalStageV1::TerminalIssued => {
            signed_valid
                && request_valid
                && sidecar_valid
                && sidecar_persistence_valid
                && terminal_valid
        }
    }
}

fn journal_path(
    directory: &Path,
    principal_mapping_identity: &str,
) -> Result<PathBuf, FinalizationJournalError> {
    let suffix = principal_mapping_identity
        .strip_prefix("sha256:")
        .filter(|suffix| suffix.len() == 64 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(FinalizationJournalError::InvalidJournal)?;
    Ok(directory.join(format!("{suffix}.json")))
}

fn verify_store(directory: &Path, expected_owner_uid: u32) -> Result<(), FinalizationJournalError> {
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| FinalizationJournalError::StoreUnavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(FinalizationJournalError::StoreUnavailable);
    }
    Ok(())
}

fn verify_file(path: &Path, expected_owner_uid: u32) -> Result<(), FinalizationJournalError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| FinalizationJournalError::StoreUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(FinalizationJournalError::StoreUnavailable);
    }
    Ok(())
}

fn write_new(path: &Path, journal: &FinalizationJournalV1) -> std::io::Result<()> {
    let bytes = serde_jcs::to_vec(journal).map_err(std::io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes).and_then(|()| file.sync_all())
}

fn replace_atomically(
    directory: &Path,
    path: &Path,
    journal: &FinalizationJournalV1,
) -> Result<(), FinalizationJournalError> {
    let temporary = directory.join(format!(
        ".{}.{}.tmp",
        path.file_stem()
            .and_then(|value| value.to_str())
            .ok_or(FinalizationJournalError::InvalidJournal)?,
        std::process::id()
    ));
    write_new(&temporary, journal).map_err(|_| FinalizationJournalError::PersistenceFailed)?;
    fs::rename(&temporary, path).map_err(|_| FinalizationJournalError::PersistenceFailed)?;
    sync_directory(directory)
}

fn sync_directory(directory: &Path) -> Result<(), FinalizationJournalError> {
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| FinalizationJournalError::PersistenceFailed)
}

#[cfg(test)]
mod tests {
    use ota_authority_protocol::{
        LAUNCHER_EXECUTION_COMPLETION, LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE,
        LAUNCHER_FINALIZATION_ARCHIVE_REQUEST, LAUNCHER_TERMINAL, LAUNCHER_TERMINAL_PERSISTENCE,
        LauncherExecutionCompletionV1, LauncherExecutionOutcomeV1, LauncherTerminalOutcomeV1,
        LauncherTerminalStageV1, SignedLauncherFinalizationArchiveV1,
        launcher_execution_completion_v1_identity,
        launcher_finalization_archive_persistence_v1_identity,
        launcher_finalization_archive_request_v1_identity,
        launcher_finalization_archive_sidecar_v1_identity,
        signed_launcher_execution_finalization_v1_identity,
        signed_launcher_finalization_archive_v1_identity,
    };
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn finalization() -> LauncherExecutionFinalizationV1 {
        let mut completion = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            lease_consumption_admission_identity: identity('1'),
            work_unit_identity: identity('2'),
            crossing_transaction_id: String::from("transaction-1"),
            pending_crossing_transaction_identity: identity('3'),
            crossing_transaction_identity: identity('4'),
            receipt_archive_identity: Some(identity('5')),
            outcome: LauncherExecutionOutcomeV1::Completed,
            exit_code: Some(0),
            receipt_status: String::from("passed"),
        };
        completion.identity =
            launcher_execution_completion_v1_identity(&completion).expect("completion identity");
        let mut finalization = LauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            completion,
            child_identity: identity('5'),
            scope_identity: identity('6'),
            child_exit_posture: None,
            observed_exit_code: Some(0),
            child_reaped: true,
            child_absent: None,
            scope_removed: true,
            cgroup_empty_or_absent: true,
            active_slot_removed: true,
        };
        finalization.identity =
            launcher_execution_finalization_v1_identity(&finalization).expect("finalization");
        finalization
    }

    fn working_directory() -> LauncherWorkingDirectoryV1 {
        let mut working_directory = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: String::from("/srv/repository"),
            device: 1,
            inode: 2,
        };
        working_directory.identity = launcher_working_directory_identity(&working_directory)
            .expect("working directory identity");
        working_directory
    }

    #[test]
    fn finalization_state_survives_every_restart_until_exact_terminal_acknowledgement() {
        let root = tempdir().expect("state root");
        let directory = root.path().join("finalization");
        fs::create_dir(&directory).expect("state directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("state permissions");
        let owner = unsafe { libc::geteuid() };
        let principal = identity('7');
        let launcher_request = identity('8');
        let finalization = finalization();
        FinalizationJournal::begin(
            &directory,
            owner,
            &principal,
            &launcher_request,
            working_directory(),
            finalization.clone(),
        )
        .expect("durable intent");
        let mut journal = FinalizationJournal::load_for_principal(&directory, owner, &principal)
            .expect("load intent")
            .expect("intent exists");
        assert_eq!(journal.journal().stage, FinalizationJournalStageV1::Intent);

        let mut signed_finalization = SignedLauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            finalization,
            producer_binding_identity: identity('9'),
            issued_at: String::from("2026-08-13T12:00:00Z"),
            key_id: String::from("attestor-1"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        signed_finalization.identity =
            signed_launcher_execution_finalization_v1_identity(&signed_finalization)
                .expect("signed finalization identity");
        journal
            .record_signed_finalization(signed_finalization.clone())
            .expect("signed finalization");

        let mut request = LauncherFinalizationArchiveRequestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_ARCHIVE_REQUEST.into(),
            request_identity: String::new(),
            authority_id: String::from("authority-1"),
            launcher_request_identity: launcher_request,
            receipt_archive_identity: identity('5'),
            crossing_transaction_identity: identity('4'),
            signed_finalization_identity: Some(signed_finalization.identity.clone()),
        };
        request.request_identity = launcher_finalization_archive_request_v1_identity(&request)
            .expect("archive request identity");
        journal
            .record_archive_request(request.clone())
            .expect("archive request");

        let mut signed_archive = SignedLauncherFinalizationArchiveV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization_identity: signed_finalization.identity.clone(),
            receipt_archive_identity: request.receipt_archive_identity.clone(),
            crossing_transaction_identity: request.crossing_transaction_identity.clone(),
            producer_binding_identity: signed_finalization.producer_binding_identity.clone(),
            issued_at: String::from("2026-08-13T12:00:01Z"),
            key_id: signed_finalization.key_id.clone(),
            algorithm: String::from("ed25519"),
            signature: String::from("archive-signature"),
        };
        signed_archive.identity = signed_launcher_finalization_archive_v1_identity(&signed_archive)
            .expect("signed archive identity");
        let mut sidecar = LauncherFinalizationArchiveSidecarV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization,
            signed_archive,
        };
        sidecar.identity =
            launcher_finalization_archive_sidecar_v1_identity(&sidecar).expect("sidecar identity");
        journal.record_sidecar(sidecar.clone()).expect("sidecar");
        drop(journal);

        let mut recovered = FinalizationJournal::load_for_principal(&directory, owner, &principal)
            .expect("load sidecar")
            .expect("sidecar state exists");
        assert_eq!(
            recovered.journal().stage,
            FinalizationJournalStageV1::SidecarIssued
        );
        let mut persistence = LauncherFinalizationArchivePersistenceV1 {
            schema_version: 1,
            message_kind: LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE.into(),
            identity: String::new(),
            request_identity: request.request_identity,
            sidecar_identity: sidecar.identity,
        };
        persistence.identity = launcher_finalization_archive_persistence_v1_identity(&persistence)
            .expect("persistence identity");
        recovered
            .record_sidecar_persistence(persistence)
            .expect("persist sidecar acknowledgement");
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: ota_authority_protocol::SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: recovered.journal().invocation_id.clone(),
            outcome: LauncherTerminalOutcomeV1::Completed,
            exit_code: Some(0),
            stage: Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved),
            finalization: Some(recovered.journal().finalization.clone()),
        };
        recovered
            .record_terminal(terminal.clone())
            .expect("persist terminal");
        drop(recovered);

        let mut recovered = FinalizationJournal::load_for_principal(&directory, owner, &principal)
            .expect("load terminal")
            .expect("terminal state exists");
        assert_eq!(recovered.journal().terminal.as_ref(), Some(&terminal));
        let mut terminal_persistence = LauncherTerminalPersistenceV1 {
            schema_version: 1,
            message_kind: LAUNCHER_TERMINAL_PERSISTENCE.into(),
            identity: String::new(),
            invocation_id: terminal.invocation_id.clone(),
            terminal_identity: launcher_terminal_frame_v1_identity(&terminal)
                .expect("terminal identity"),
        };
        terminal_persistence.identity =
            launcher_terminal_persistence_v1_identity(&terminal_persistence)
                .expect("terminal persistence identity");
        let mut wrong = terminal_persistence.clone();
        wrong.terminal_identity = identity('f');
        wrong.identity =
            launcher_terminal_persistence_v1_identity(&wrong).expect("wrong persistence identity");
        assert!(recovered.acknowledge_terminal_and_finalize(&wrong).is_err());
        recovered
            .acknowledge_terminal_and_finalize(&terminal_persistence)
            .expect("finalize after terminal acknowledgement");
        assert!(
            FinalizationJournal::load_for_principal(&directory, owner, &principal)
                .expect("load finalized state")
                .is_none()
        );
    }
}
