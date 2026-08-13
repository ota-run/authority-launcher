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

//! Durable launcher-owned active-slot state.
//!
//! A slot is created and fsynced before the launcher may fork a governed Ota child. Dropping the
//! handle deliberately retains the journal for recovery; only explicit terminal cleanup removes
//! it after the child boundary has been confirmed absent.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ota_authority_protocol::{
    AuthorizationDecision, AuthorizationDecisionRelayEvidenceV1, LauncherChildProcessV1,
    LauncherExecutionCompletionV1, LauncherSystemdScopeV1, LauncherWorkingDirectoryV1,
    LeaseConsumptionIntentRelayEvidenceV1, LeaseConsumptionRelayEvidenceV1,
    authorization_decision_relay_evidence_v1_identity, launcher_child_process_identity,
    launcher_execution_completion_v1_identity, launcher_systemd_scope_identity,
    launcher_working_directory_identity, lease_consumption_intent_relay_evidence_v1_identity,
    lease_consumption_relay_evidence_v1_identity, message_identity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::verify_protected_directory;

const ACTIVE_SLOT_IDENTITY_DOMAIN_V1: &[u8] = b"ota.authority-launcher.active-slot.v1\0";
const MAX_ACTIVE_SLOT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActiveSlotStage {
    Intent,
    ChildPrepared,
    ScopeAttached,
    AuthorizationDecisionVerified,
    LeaseConsumptionIntentRecorded,
    LeaseConsumptionVerified,
    ExecutionCompletionRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveSlotJournalV1 {
    pub schema_version: u32,
    pub identity: String,
    pub stage: ActiveSlotStage,
    pub invocation_id: String,
    pub principal_mapping_identity: String,
    pub request_identity: String,
    pub working_directory: LauncherWorkingDirectoryV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<LauncherChildProcessV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<LauncherSystemdScopeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_decision: Option<AuthorizationDecisionRelayEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_consumption_intent: Option<LeaseConsumptionIntentRelayEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_consumption: Option<LeaseConsumptionRelayEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_completion: Option<LauncherExecutionCompletionV1>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ActiveSlotError {
    #[error("the protected active-slot store is unavailable")]
    StoreUnavailable,
    #[error("the protected active-slot store is invalid")]
    StoreInvalid,
    #[error("the principal already has an active launcher invocation")]
    AlreadyActive,
    #[error("the active-slot journal is invalid")]
    InvalidJournal,
    #[error("the active-slot journal could not be persisted")]
    PersistenceFailed,
}

pub(crate) struct ActiveSlot {
    directory: PathBuf,
    path: PathBuf,
    journal: ActiveSlotJournalV1,
}

impl ActiveSlot {
    pub(crate) fn load_all(
        directory: &Path,
        expected_owner_uid: u32,
        trusted_root: &Path,
    ) -> Result<Vec<Self>, ActiveSlotError> {
        verify_store(directory, expected_owner_uid, trusted_root)?;
        let mut canonical = BTreeMap::new();
        let mut temporary = BTreeMap::new();
        let mut temporary_paths = Vec::new();
        let mut entries = fs::read_dir(directory)
            .map_err(|_| ActiveSlotError::StoreUnavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ActiveSlotError::StoreUnavailable)?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ActiveSlotError::StoreInvalid)?;
            verify_journal_file(&path, expected_owner_uid)?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                temporary_paths.push((path, name));
                continue;
            }
            let journal = load_journal(&path)?;
            if slot_path(directory, journal.principal_mapping_identity.as_str())? != path {
                return Err(ActiveSlotError::InvalidJournal);
            }
            if canonical
                .insert(journal.principal_mapping_identity.clone(), (path, journal))
                .is_some()
            {
                return Err(ActiveSlotError::InvalidJournal);
            }
        }

        for (path, name) in temporary_paths {
            let invocation_id = name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix(".tmp"))
                .filter(|value| is_bounded_label(value))
                .ok_or(ActiveSlotError::InvalidJournal)?;
            let journal = match load_journal(&path) {
                Ok(journal) => journal,
                Err(ActiveSlotError::InvalidJournal) => {
                    let matching = canonical
                        .values()
                        .filter(|(_, journal)| journal.invocation_id == invocation_id)
                        .count();
                    if matching != 1 {
                        return Err(ActiveSlotError::InvalidJournal);
                    }
                    fs::remove_file(&path).map_err(|_| ActiveSlotError::PersistenceFailed)?;
                    sync_directory(directory)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if name != format!(".{}.tmp", journal.invocation_id)
                || journal.stage == ActiveSlotStage::Intent
            {
                return Err(ActiveSlotError::InvalidJournal);
            }
            if temporary
                .insert(journal.principal_mapping_identity.clone(), (path, journal))
                .is_some()
            {
                return Err(ActiveSlotError::InvalidJournal);
            }
        }

        for (_, (temporary_path, recovered)) in temporary {
            let Some((canonical_path, intent)) =
                canonical.get_mut(recovered.principal_mapping_identity.as_str())
            else {
                return Err(ActiveSlotError::InvalidJournal);
            };
            if !is_direct_successor(intent, &recovered)
                || intent.invocation_id != recovered.invocation_id
                || intent.request_identity != recovered.request_identity
                || intent.working_directory != recovered.working_directory
            {
                return Err(ActiveSlotError::InvalidJournal);
            }
            fs::rename(&temporary_path, &*canonical_path)
                .map_err(|_| ActiveSlotError::PersistenceFailed)?;
            *intent = recovered;
            sync_directory(directory)?;
        }

        Ok(canonical
            .into_values()
            .map(|(path, journal)| Self {
                directory: directory.into(),
                path,
                journal,
            })
            .collect())
    }

    pub(crate) fn begin(
        directory: &Path,
        expected_owner_uid: u32,
        trusted_root: &Path,
        invocation_id: &str,
        principal_mapping_identity: &str,
        request_identity: &str,
        working_directory: LauncherWorkingDirectoryV1,
    ) -> Result<Self, ActiveSlotError> {
        verify_store(directory, expected_owner_uid, trusted_root)?;
        let path = slot_path(directory, principal_mapping_identity)?;
        let mut journal = ActiveSlotJournalV1 {
            schema_version: 1,
            identity: String::new(),
            stage: ActiveSlotStage::Intent,
            invocation_id: invocation_id.into(),
            principal_mapping_identity: principal_mapping_identity.into(),
            request_identity: request_identity.into(),
            working_directory,
            child: None,
            scope: None,
            authorization_decision: None,
            lease_consumption_intent: None,
            lease_consumption: None,
            execution_completion: None,
        };
        journal.identity = active_slot_identity(&journal)?;
        write_new(&path, &journal)?;
        sync_directory(directory)?;
        Ok(Self {
            directory: directory.into(),
            path,
            journal,
        })
    }

    pub(crate) fn record_child(
        &mut self,
        child: LauncherChildProcessV1,
    ) -> Result<(), ActiveSlotError> {
        if self.journal.stage != ActiveSlotStage::Intent || self.journal.child.is_some() {
            return Err(ActiveSlotError::InvalidJournal);
        }
        self.journal.stage = ActiveSlotStage::ChildPrepared;
        self.journal.child = Some(child);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn child(&self) -> Option<&LauncherChildProcessV1> {
        self.journal.child.as_ref()
    }

    pub(crate) fn principal_mapping_identity(&self) -> &str {
        self.journal.principal_mapping_identity.as_str()
    }

    pub(crate) fn request_identity(&self) -> &str {
        self.journal.request_identity.as_str()
    }

    pub(crate) fn working_directory(&self) -> &LauncherWorkingDirectoryV1 {
        &self.journal.working_directory
    }

    pub(crate) fn record_scope(
        &mut self,
        scope: LauncherSystemdScopeV1,
    ) -> Result<(), ActiveSlotError> {
        if self.journal.stage != ActiveSlotStage::ChildPrepared
            || self.journal.child.is_none()
            || self.journal.scope.is_some()
        {
            return Err(ActiveSlotError::InvalidJournal);
        }
        self.journal.stage = ActiveSlotStage::ScopeAttached;
        self.journal.scope = Some(scope);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn scope(&self) -> Option<&LauncherSystemdScopeV1> {
        self.journal.scope.as_ref()
    }

    pub(crate) fn record_authorization_decision(
        &mut self,
        evidence: AuthorizationDecisionRelayEvidenceV1,
    ) -> Result<(), ActiveSlotError> {
        if authorization_decision_relay_evidence_v1_identity(&evidence)
            .ok()
            .as_deref()
            != Some(evidence.identity.as_str())
            || self.journal.child.is_none()
            || self.journal.scope.is_none()
        {
            return Err(ActiveSlotError::InvalidJournal);
        }
        match (
            &self.journal.stage,
            self.journal.authorization_decision.as_ref(),
        ) {
            (ActiveSlotStage::ScopeAttached, None) => {}
            (ActiveSlotStage::AuthorizationDecisionVerified, Some(previous))
                if previous == &evidence =>
            {
                return Ok(());
            }
            (ActiveSlotStage::AuthorizationDecisionVerified, Some(previous))
                if previous.authorization_decision.payload.decision
                    == AuthorizationDecision::Pending
                    && same_authorization_request(previous, &evidence) => {}
            _ => return Err(ActiveSlotError::InvalidJournal),
        }
        self.journal.stage = ActiveSlotStage::AuthorizationDecisionVerified;
        self.journal.authorization_decision = Some(evidence);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn record_lease_consumption(
        &mut self,
        evidence: LeaseConsumptionRelayEvidenceV1,
    ) -> Result<(), ActiveSlotError> {
        if lease_consumption_relay_evidence_v1_identity(&evidence)
            .ok()
            .as_deref()
            != Some(evidence.identity.as_str())
            || self.journal.stage != ActiveSlotStage::LeaseConsumptionIntentRecorded
            || self
                .journal
                .authorization_decision
                .as_ref()
                .is_none_or(|decision| {
                    decision.identity != evidence.authorization_decision_relay_identity
                        || decision.authorization_decision.payload.decision
                            != AuthorizationDecision::Allowed
                })
            || self.journal.lease_consumption.is_some()
        {
            return Err(ActiveSlotError::InvalidJournal);
        }
        self.journal.stage = ActiveSlotStage::LeaseConsumptionVerified;
        self.journal.lease_consumption = Some(evidence);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn record_lease_consumption_intent(
        &mut self,
        evidence: LeaseConsumptionIntentRelayEvidenceV1,
    ) -> Result<(), ActiveSlotError> {
        if lease_consumption_intent_relay_evidence_v1_identity(&evidence)
            .ok()
            .as_deref()
            != Some(evidence.identity.as_str())
            || self.journal.stage != ActiveSlotStage::AuthorizationDecisionVerified
            || self
                .journal
                .authorization_decision
                .as_ref()
                .is_none_or(|decision| {
                    decision.identity != evidence.authorization_decision_relay_identity
                        || decision.authorization_decision.payload.decision
                            != AuthorizationDecision::Allowed
                })
            || self.journal.lease_consumption_intent.is_some()
            || self.journal.lease_consumption.is_some()
        {
            return Err(ActiveSlotError::InvalidJournal);
        }
        self.journal.stage = ActiveSlotStage::LeaseConsumptionIntentRecorded;
        self.journal.lease_consumption_intent = Some(evidence);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn record_execution_completion(
        &mut self,
        completion: LauncherExecutionCompletionV1,
    ) -> Result<(), ActiveSlotError> {
        if launcher_execution_completion_v1_identity(&completion)
            .ok()
            .as_deref()
            != Some(completion.identity.as_str())
            || self.journal.stage != ActiveSlotStage::LeaseConsumptionVerified
            || self.journal.execution_completion.is_some()
            || self
                .journal
                .lease_consumption
                .as_ref()
                .is_none_or(|consumption| {
                    completion.invocation_id != self.journal.invocation_id
                        || completion.lease_consumption_admission_identity
                            != consumption.admission.identity
                        || completion.work_unit_identity != consumption.admission.work_unit_identity
                        || completion.crossing_transaction_id
                            != consumption.admission.crossing_transaction_id
                        || completion.pending_crossing_transaction_identity
                            != consumption.admission.crossing_transaction_identity
                })
        {
            return Err(ActiveSlotError::InvalidJournal);
        }
        self.journal.stage = ActiveSlotStage::ExecutionCompletionRecorded;
        self.journal.execution_completion = Some(completion);
        self.journal.identity = active_slot_identity(&self.journal)?;
        replace_atomically(&self.directory, &self.path, &self.journal)
    }

    pub(crate) fn execution_completion(&self) -> Option<&LauncherExecutionCompletionV1> {
        self.journal.execution_completion.as_ref()
    }

    pub(crate) fn has_lease_consumption(&self) -> bool {
        matches!(
            self.journal.stage,
            ActiveSlotStage::LeaseConsumptionVerified
                | ActiveSlotStage::ExecutionCompletionRecorded
        ) && self.journal.lease_consumption.is_some()
    }

    pub(crate) fn has_lease_consumption_intent(&self) -> bool {
        matches!(
            self.journal.stage,
            ActiveSlotStage::LeaseConsumptionIntentRecorded
                | ActiveSlotStage::LeaseConsumptionVerified
                | ActiveSlotStage::ExecutionCompletionRecorded
        ) && self.journal.lease_consumption_intent.is_some()
    }

    pub(crate) fn finalize(self) -> Result<(), ActiveSlotError> {
        fs::remove_file(&self.path).map_err(|_| ActiveSlotError::PersistenceFailed)?;
        sync_directory(&self.directory)
    }
}

fn is_direct_successor(current: &ActiveSlotJournalV1, recovered: &ActiveSlotJournalV1) -> bool {
    match (current.stage, recovered.stage) {
        (ActiveSlotStage::Intent, ActiveSlotStage::ChildPrepared) => {
            current.child.is_none() && current.scope.is_none() && recovered.scope.is_none()
        }
        (ActiveSlotStage::ChildPrepared, ActiveSlotStage::ScopeAttached) => {
            current.child == recovered.child
                && current.scope.is_none()
                && recovered.scope.is_some()
                && current.authorization_decision.is_none()
                && recovered.authorization_decision.is_none()
        }
        (ActiveSlotStage::ScopeAttached, ActiveSlotStage::AuthorizationDecisionVerified) => {
            current.child == recovered.child
                && current.scope == recovered.scope
                && current.authorization_decision.is_none()
                && recovered.authorization_decision.is_some()
        }
        (
            ActiveSlotStage::AuthorizationDecisionVerified,
            ActiveSlotStage::LeaseConsumptionIntentRecorded,
        ) => {
            current.child == recovered.child
                && current.scope == recovered.scope
                && current.authorization_decision == recovered.authorization_decision
                && current.lease_consumption_intent.is_none()
                && recovered.lease_consumption_intent.is_some()
                && recovered.lease_consumption.is_none()
        }
        (
            ActiveSlotStage::LeaseConsumptionIntentRecorded,
            ActiveSlotStage::LeaseConsumptionVerified,
        ) => {
            current.child == recovered.child
                && current.scope == recovered.scope
                && current.authorization_decision == recovered.authorization_decision
                && current.lease_consumption_intent == recovered.lease_consumption_intent
                && current.lease_consumption.is_none()
                && recovered.lease_consumption.is_some()
        }
        (
            ActiveSlotStage::LeaseConsumptionVerified,
            ActiveSlotStage::ExecutionCompletionRecorded,
        ) => {
            current.child == recovered.child
                && current.scope == recovered.scope
                && current.authorization_decision == recovered.authorization_decision
                && current.lease_consumption_intent == recovered.lease_consumption_intent
                && current.lease_consumption == recovered.lease_consumption
                && current.execution_completion.is_none()
                && recovered.execution_completion.is_some()
        }
        (
            ActiveSlotStage::AuthorizationDecisionVerified,
            ActiveSlotStage::AuthorizationDecisionVerified,
        ) => {
            current.child == recovered.child
                && current.scope == recovered.scope
                && current
                    .authorization_decision
                    .as_ref()
                    .zip(recovered.authorization_decision.as_ref())
                    .is_some_and(|(previous, next)| {
                        previous == next
                            || (previous.authorization_decision.payload.decision
                                == AuthorizationDecision::Pending
                                && same_authorization_request(previous, next))
                    })
        }
        _ => false,
    }
}

pub(crate) fn active_slot_identity(
    journal: &ActiveSlotJournalV1,
) -> Result<String, ActiveSlotError> {
    if journal.schema_version != 1
        || !is_bounded_label(journal.invocation_id.as_str())
        || !is_sha256_identity(journal.principal_mapping_identity.as_str())
        || !is_sha256_identity(journal.request_identity.as_str())
        || launcher_working_directory_identity(&journal.working_directory)
            .ok()
            .as_deref()
            != Some(journal.working_directory.identity.as_str())
        || match journal.stage {
            ActiveSlotStage::Intent => {
                journal.child.is_some()
                    || journal.scope.is_some()
                    || journal.authorization_decision.is_some()
                    || journal.lease_consumption_intent.is_some()
                    || journal.lease_consumption.is_some()
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::ChildPrepared => {
                journal.child.as_ref().is_none_or(|child| {
                    launcher_child_process_identity(child).ok().as_deref()
                        != Some(child.identity.as_str())
                        || child.invocation_id != journal.invocation_id
                        || child.request_identity != journal.request_identity
                        || child.principal_mapping_identity != journal.principal_mapping_identity
                        || child.working_directory_identity != journal.working_directory.identity
                }) || journal.scope.is_some()
                    || journal.authorization_decision.is_some()
                    || journal.lease_consumption_intent.is_some()
                    || journal.lease_consumption.is_some()
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::ScopeAttached => {
                journal.child.as_ref().is_none_or(|child| {
                    launcher_child_process_identity(child).ok().as_deref()
                        != Some(child.identity.as_str())
                        || child.invocation_id != journal.invocation_id
                        || child.request_identity != journal.request_identity
                        || child.principal_mapping_identity != journal.principal_mapping_identity
                        || child.working_directory_identity != journal.working_directory.identity
                }) || journal.scope.as_ref().is_none_or(|scope| {
                    launcher_systemd_scope_identity(scope).ok().as_deref()
                        != Some(scope.identity.as_str())
                        || scope.invocation_id != journal.invocation_id
                        || scope.request_identity != journal.request_identity
                        || Some(scope.child_identity.as_str())
                            != journal.child.as_ref().map(|child| child.identity.as_str())
                        || Some(scope.child_pid) != journal.child.as_ref().map(|child| child.pid)
                }) || journal.authorization_decision.is_some()
                    || journal.lease_consumption_intent.is_some()
                    || journal.lease_consumption.is_some()
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::AuthorizationDecisionVerified => {
                journal.child.as_ref().is_none_or(|child| {
                    launcher_child_process_identity(child).ok().as_deref()
                        != Some(child.identity.as_str())
                        || child.invocation_id != journal.invocation_id
                        || child.request_identity != journal.request_identity
                        || child.principal_mapping_identity != journal.principal_mapping_identity
                        || child.working_directory_identity != journal.working_directory.identity
                }) || journal.scope.as_ref().is_none_or(|scope| {
                    launcher_systemd_scope_identity(scope).ok().as_deref()
                        != Some(scope.identity.as_str())
                        || scope.invocation_id != journal.invocation_id
                        || scope.request_identity != journal.request_identity
                        || Some(scope.child_identity.as_str())
                            != journal.child.as_ref().map(|child| child.identity.as_str())
                        || Some(scope.child_pid) != journal.child.as_ref().map(|child| child.pid)
                }) || journal
                    .authorization_decision
                    .as_ref()
                    .is_none_or(|evidence| {
                        authorization_decision_relay_evidence_v1_identity(evidence)
                            .ok()
                            .as_deref()
                            != Some(evidence.identity.as_str())
                    })
                    || journal.lease_consumption_intent.is_some()
                    || journal.lease_consumption.is_some()
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::LeaseConsumptionIntentRecorded => {
                journal.child.is_none()
                    || journal.scope.is_none()
                    || journal
                        .authorization_decision
                        .as_ref()
                        .is_none_or(|decision| {
                            decision.authorization_decision.payload.decision
                                != AuthorizationDecision::Allowed
                        })
                    || journal
                        .lease_consumption_intent
                        .as_ref()
                        .is_none_or(|intent| {
                            lease_consumption_intent_relay_evidence_v1_identity(intent)
                                .ok()
                                .as_deref()
                                != Some(intent.identity.as_str())
                                || Some(intent.authorization_decision_relay_identity.as_str())
                                    != journal
                                        .authorization_decision
                                        .as_ref()
                                        .map(|decision| decision.identity.as_str())
                        })
                    || journal.lease_consumption.is_some()
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::LeaseConsumptionVerified => {
                journal.child.as_ref().is_none_or(|child| {
                    launcher_child_process_identity(child).ok().as_deref()
                        != Some(child.identity.as_str())
                        || child.invocation_id != journal.invocation_id
                        || child.request_identity != journal.request_identity
                        || child.principal_mapping_identity != journal.principal_mapping_identity
                        || child.working_directory_identity != journal.working_directory.identity
                }) || journal.scope.as_ref().is_none_or(|scope| {
                    launcher_systemd_scope_identity(scope).ok().as_deref()
                        != Some(scope.identity.as_str())
                        || scope.invocation_id != journal.invocation_id
                        || scope.request_identity != journal.request_identity
                        || Some(scope.child_identity.as_str())
                            != journal.child.as_ref().map(|child| child.identity.as_str())
                        || Some(scope.child_pid) != journal.child.as_ref().map(|child| child.pid)
                }) || journal
                    .authorization_decision
                    .as_ref()
                    .is_none_or(|decision| {
                        authorization_decision_relay_evidence_v1_identity(decision)
                            .ok()
                            .as_deref()
                            != Some(decision.identity.as_str())
                            || decision.authorization_decision.payload.decision
                                != AuthorizationDecision::Allowed
                    })
                    || journal.lease_consumption.as_ref().is_none_or(|evidence| {
                        lease_consumption_relay_evidence_v1_identity(evidence)
                            .ok()
                            .as_deref()
                            != Some(evidence.identity.as_str())
                            || Some(evidence.authorization_decision_relay_identity.as_str())
                                != journal
                                    .authorization_decision
                                    .as_ref()
                                    .map(|decision| decision.identity.as_str())
                    })
                    || journal
                        .lease_consumption_intent
                        .as_ref()
                        .is_none_or(|intent| {
                            lease_consumption_intent_relay_evidence_v1_identity(intent)
                                .ok()
                                .as_deref()
                                != Some(intent.identity.as_str())
                                || journal.lease_consumption.as_ref().is_none_or(|evidence| {
                                    intent.consume_request_identity
                                        != evidence.consume_request_identity
                                })
                        })
                    || journal.execution_completion.is_some()
            }
            ActiveSlotStage::ExecutionCompletionRecorded => {
                journal.child.is_none()
                    || journal.scope.is_none()
                    || journal.authorization_decision.is_none()
                    || journal.lease_consumption_intent.is_none()
                    || journal.lease_consumption.is_none()
                    || journal
                        .execution_completion
                        .as_ref()
                        .is_none_or(|completion| {
                            launcher_execution_completion_v1_identity(completion)
                                .ok()
                                .as_deref()
                                != Some(completion.identity.as_str())
                                || completion.invocation_id != journal.invocation_id
                                || journal
                                    .lease_consumption
                                    .as_ref()
                                    .is_none_or(|consumption| {
                                        completion.lease_consumption_admission_identity
                                            != consumption.admission.identity
                                            || completion.work_unit_identity
                                                != consumption.admission.work_unit_identity
                                            || completion.crossing_transaction_id
                                                != consumption.admission.crossing_transaction_id
                                            || completion.pending_crossing_transaction_identity
                                                != consumption
                                                    .admission
                                                    .crossing_transaction_identity
                                    })
                        })
            }
        }
    {
        return Err(ActiveSlotError::InvalidJournal);
    }
    let mut canonical = journal.clone();
    canonical.identity.clear();
    message_identity(ACTIVE_SLOT_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| ActiveSlotError::InvalidJournal)
}

fn same_authorization_request(
    previous: &AuthorizationDecisionRelayEvidenceV1,
    next: &AuthorizationDecisionRelayEvidenceV1,
) -> bool {
    previous.request_identity == next.request_identity
        && previous.authorization_decision.payload.binding_identity
            == next.authorization_decision.payload.binding_identity
        && previous.authorization_decision.payload.authority_id
            == next.authorization_decision.payload.authority_id
        && previous.authorization_decision.payload.attestation_identity
            == next.authorization_decision.payload.attestation_identity
        && previous
            .authorization_decision
            .payload
            .challenge_nonce_commitment
            == next
                .authorization_decision
                .payload
                .challenge_nonce_commitment
        && previous.authorization_decision.payload.work_unit_identity
            == next.authorization_decision.payload.work_unit_identity
        && previous.authorization_decision.payload.contract_identity
            == next.authorization_decision.payload.contract_identity
        && previous
            .authorization_decision
            .payload
            .semantic_scope_identity
            == next.authorization_decision.payload.semantic_scope_identity
}

fn verify_store(
    directory: &Path,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<(), ActiveSlotError> {
    if verify_protected_directory(directory, expected_owner_uid, trusted_root).is_err() {
        return Err(ActiveSlotError::StoreInvalid);
    }
    let metadata =
        fs::symlink_metadata(directory).map_err(|_| ActiveSlotError::StoreUnavailable)?;
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(ActiveSlotError::StoreInvalid);
    }
    Ok(())
}

fn slot_path(directory: &Path, mapping_identity: &str) -> Result<PathBuf, ActiveSlotError> {
    if !is_sha256_identity(mapping_identity) {
        return Err(ActiveSlotError::InvalidJournal);
    }
    Ok(directory.join(format!("{}.json", &mapping_identity[7..])))
}

fn write_new(path: &Path, journal: &ActiveSlotJournalV1) -> Result<(), ActiveSlotError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ActiveSlotError::AlreadyActive);
        }
        Err(_) => return Err(ActiveSlotError::PersistenceFailed),
    };
    let bytes = serde_json::to_vec(journal).map_err(|_| ActiveSlotError::InvalidJournal)?;
    file.write_all(bytes.as_slice())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| ActiveSlotError::PersistenceFailed)
}

fn replace_atomically(
    directory: &Path,
    path: &Path,
    journal: &ActiveSlotJournalV1,
) -> Result<(), ActiveSlotError> {
    let temporary = directory.join(format!(".{}.tmp", journal.invocation_id));
    write_new(&temporary, journal)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        let _ = error;
        return Err(ActiveSlotError::PersistenceFailed);
    }
    sync_directory(directory)
}

fn sync_directory(directory: &Path) -> Result<(), ActiveSlotError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| ActiveSlotError::PersistenceFailed)
}

fn verify_journal_file(path: &Path, expected_owner_uid: u32) -> Result<(), ActiveSlotError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ActiveSlotError::StoreUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > MAX_ACTIVE_SLOT_BYTES
    {
        return Err(ActiveSlotError::StoreInvalid);
    }
    Ok(())
}

fn is_bounded_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_sha256_identity(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn load_journal(path: &Path) -> Result<ActiveSlotJournalV1, ActiveSlotError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| ActiveSlotError::StoreUnavailable)?;
    let mut bytes = Vec::new();
    BufReader::new(file)
        .take(MAX_ACTIVE_SLOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActiveSlotError::StoreUnavailable)?;
    if bytes.len() as u64 > MAX_ACTIVE_SLOT_BYTES {
        return Err(ActiveSlotError::StoreInvalid);
    }
    let journal: ActiveSlotJournalV1 =
        serde_json::from_slice(&bytes).map_err(|_| ActiveSlotError::InvalidJournal)?;
    if active_slot_identity(&journal).ok().as_deref() != Some(journal.identity.as_str()) {
        return Err(ActiveSlotError::InvalidJournal);
    }
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use ota_authority_protocol::{
        AUTHORIZATION_DECISION, AUTHORIZATION_DECISION_ADMISSION, AUTHORIZATION_DECISION_DOMAIN_V1,
        AuthorizationDecision, AuthorizationDecisionAdmissionV1, AuthorizationDecisionPayload,
        AuthorizationDecisionRelayEvidenceV1, LauncherChildProcessV1, LauncherSystemdScopeV1,
        LauncherWorkingDirectoryV1, SignedBrokerMessage,
        authorization_decision_admission_v1_identity,
        authorization_decision_relay_evidence_v1_identity, launcher_child_process_identity,
        launcher_systemd_scope_identity, launcher_working_directory_identity, message_identity,
    };
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn working_directory() -> LauncherWorkingDirectoryV1 {
        let mut directory = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: "/srv/repositories/project".into(),
            device: 8,
            inode: 42,
        };
        directory.identity =
            launcher_working_directory_identity(&directory).expect("directory identity");
        directory
    }

    fn prepared_journal(
        invocation_id: &str,
        mapping_identity: &str,
        request_identity: &str,
    ) -> ActiveSlotJournalV1 {
        let working_directory = working_directory();
        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: invocation_id.into(),
            request_identity: request_identity.into(),
            pid: 4242,
            process_start_time_identity: identity('c'),
            ota_binary_identity: identity('d'),
            principal_mapping_identity: mapping_identity.into(),
            working_directory_identity: working_directory.identity.clone(),
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        let mut journal = ActiveSlotJournalV1 {
            schema_version: 1,
            identity: String::new(),
            stage: ActiveSlotStage::ChildPrepared,
            invocation_id: invocation_id.into(),
            principal_mapping_identity: mapping_identity.into(),
            request_identity: request_identity.into(),
            working_directory,
            child: Some(child),
            scope: None,
            authorization_decision: None,
            lease_consumption_intent: None,
            lease_consumption: None,
            execution_completion: None,
        };
        journal.identity = active_slot_identity(&journal).expect("journal identity");
        journal
    }

    fn attached_scope(child: &LauncherChildProcessV1) -> LauncherSystemdScopeV1 {
        let unit_name = format!(
            "ota-authority-invocation-{}.scope",
            child.request_identity.trim_start_matches("sha256:")
        );
        let mut scope = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: child.invocation_id.clone(),
            request_identity: child.request_identity.clone(),
            child_identity: child.identity.clone(),
            child_pid: child.pid,
            unit_name: unit_name.clone(),
            unit_object_path: format!("/org/freedesktop/systemd1/unit/{unit_name}"),
            slice: String::from("ota-authority-invocations.slice"),
            control_group: format!("/ota-authority-invocations.slice/{unit_name}"),
            delegate: false,
            kill_mode: String::from("control-group"),
            collect_mode: String::from("inactive-or-failed"),
        };
        scope.identity = launcher_systemd_scope_identity(&scope).expect("scope identity");
        scope
    }

    fn decision_evidence(
        decision: AuthorizationDecision,
        revision: u64,
        semantic_scope_identity: String,
    ) -> AuthorizationDecisionRelayEvidenceV1 {
        let request_identity = identity('1');
        let signed = SignedBrokerMessage {
            payload: AuthorizationDecisionPayload {
                message_kind: AUTHORIZATION_DECISION.into(),
                request_identity: request_identity.clone(),
                binding_identity: identity('2'),
                authority_id: String::from("release"),
                attestation_identity: identity('3'),
                challenge_nonce_commitment: identity('4'),
                work_unit_identity: identity('5'),
                contract_identity: identity('6'),
                semantic_scope_identity,
                decision,
                approval_reference: Some(format!("approval:{revision}")),
                broker_revision: revision,
                issued_at: String::from("2026-08-11T00:00:00Z"),
                expires_at: String::from("2026-08-11T00:01:00Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: format!("signature-{revision}"),
        };
        let decision_identity =
            message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), &signed)
                .expect("decision identity");
        let mut admission = AuthorizationDecisionAdmissionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: AUTHORIZATION_DECISION_ADMISSION.into(),
            request_identity: request_identity.clone(),
            authorization_decision_identity: decision_identity.clone(),
            binding_identity: signed.payload.binding_identity.clone(),
            attestation_identity: signed.payload.attestation_identity.clone(),
            work_unit_identity: signed.payload.work_unit_identity.clone(),
            contract_identity: signed.payload.contract_identity.clone(),
            semantic_scope_identity: signed.payload.semantic_scope_identity.clone(),
            decision,
        };
        admission.identity =
            authorization_decision_admission_v1_identity(&admission).expect("admission identity");
        let mut evidence = AuthorizationDecisionRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            request_identity,
            authorization_decision: signed,
            authorization_decision_identity: decision_identity,
            admission,
        };
        evidence.identity = authorization_decision_relay_evidence_v1_identity(&evidence)
            .expect("relay evidence identity");
        evidence
    }

    #[test]
    fn slot_is_durable_before_child_and_removed_only_by_finalization() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        let mapping_identity = identity('a');
        let request_identity = identity('b');
        let mut slot = ActiveSlot::begin(
            temporary.path(),
            owner,
            temporary.path(),
            "invocation-123",
            mapping_identity.as_str(),
            request_identity.as_str(),
            working_directory(),
        )
        .expect("begin slot");
        let path = slot.path.clone();
        let intent = load_journal(&path).expect("intent journal");
        assert_eq!(intent.stage, ActiveSlotStage::Intent);
        assert!(intent.child.is_none());
        assert!(matches!(
            ActiveSlot::begin(
                temporary.path(),
                owner,
                temporary.path(),
                "invocation-456",
                mapping_identity.as_str(),
                request_identity.as_str(),
                working_directory(),
            ),
            Err(ActiveSlotError::AlreadyActive)
        ));

        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: intent.invocation_id.clone(),
            request_identity: intent.request_identity.clone(),
            pid: 4242,
            process_start_time_identity: identity('c'),
            ota_binary_identity: identity('d'),
            principal_mapping_identity: mapping_identity,
            working_directory_identity: intent.working_directory.identity,
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        slot.record_child(child.clone()).expect("record child");
        let prepared = load_journal(&path).expect("prepared journal");
        assert_eq!(prepared.stage, ActiveSlotStage::ChildPrepared);
        assert_eq!(prepared.child, Some(child.clone()));
        let scope = attached_scope(&child);
        slot.record_scope(scope.clone()).expect("record scope");
        let attached = load_journal(&path).expect("scope journal");
        assert_eq!(attached.stage, ActiveSlotStage::ScopeAttached);
        assert_eq!(attached.scope, Some(scope));

        drop(slot);
        assert!(
            path.exists(),
            "dropping the slot must retain recovery state"
        );
        let mut recovered = ActiveSlot::load_all(temporary.path(), owner, temporary.path())
            .expect("load retained journal");
        assert_eq!(recovered.len(), 1);
        let recovered_slot = recovered.pop().expect("recovered slot");
        recovered_slot.finalize().expect("finalize slot");
        assert!(!path.exists());
    }

    #[test]
    fn slot_durably_reconciles_pending_then_allowed_decision() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        let mapping_identity = identity('a');
        let invocation_request_identity = identity('b');
        let mut slot = ActiveSlot::begin(
            temporary.path(),
            owner,
            temporary.path(),
            "invocation-decision",
            mapping_identity.as_str(),
            invocation_request_identity.as_str(),
            working_directory(),
        )
        .expect("begin slot");
        let prepared = prepared_journal(
            "invocation-decision",
            mapping_identity.as_str(),
            invocation_request_identity.as_str(),
        );
        let child = prepared.child.expect("prepared child");
        slot.record_child(child.clone()).expect("record child");
        slot.record_scope(attached_scope(&child))
            .expect("record scope");

        let pending = decision_evidence(AuthorizationDecision::Pending, 1, identity('7'));
        slot.record_authorization_decision(pending.clone())
            .expect("record pending decision");
        let pending_journal = load_journal(&slot.path).expect("pending journal");
        assert_eq!(
            pending_journal.stage,
            ActiveSlotStage::AuthorizationDecisionVerified
        );
        assert_eq!(pending_journal.authorization_decision, Some(pending));

        let allowed = decision_evidence(AuthorizationDecision::Allowed, 2, identity('7'));
        slot.record_authorization_decision(allowed.clone())
            .expect("record allowed decision");
        let allowed_journal = load_journal(&slot.path).expect("allowed journal");
        assert_eq!(allowed_journal.authorization_decision, Some(allowed));

        let substituted = decision_evidence(AuthorizationDecision::Allowed, 3, identity('8'));
        assert_eq!(
            slot.record_authorization_decision(substituted),
            Err(ActiveSlotError::InvalidJournal)
        );
        slot.finalize().expect("finalize slot");
    }

    #[test]
    fn pending_decision_temporary_successor_is_promoted_for_recovery() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        let mapping_identity = identity('a');
        let invocation_request_identity = identity('b');
        let mut slot = ActiveSlot::begin(
            temporary.path(),
            owner,
            temporary.path(),
            "invocation-decision-recovery",
            mapping_identity.as_str(),
            invocation_request_identity.as_str(),
            working_directory(),
        )
        .expect("begin slot");
        let prepared = prepared_journal(
            "invocation-decision-recovery",
            mapping_identity.as_str(),
            invocation_request_identity.as_str(),
        );
        let child = prepared.child.expect("prepared child");
        slot.record_child(child.clone()).expect("record child");
        slot.record_scope(attached_scope(&child))
            .expect("record scope");
        slot.record_authorization_decision(decision_evidence(
            AuthorizationDecision::Pending,
            1,
            identity('7'),
        ))
        .expect("record pending decision");

        let allowed = decision_evidence(AuthorizationDecision::Allowed, 2, identity('7'));
        let mut successor = slot.journal.clone();
        successor.authorization_decision = Some(allowed.clone());
        successor.identity = active_slot_identity(&successor).expect("successor identity");
        let temporary_path = temporary.path().join(".invocation-decision-recovery.tmp");
        write_new(&temporary_path, &successor).expect("temporary decision journal");
        sync_directory(temporary.path()).expect("temporary journal sync");
        drop(slot);

        let mut recovered = ActiveSlot::load_all(temporary.path(), owner, temporary.path())
            .expect("load decision successor");
        assert!(!temporary_path.exists());
        assert_eq!(recovered.len(), 1);
        let promoted = recovered.pop().expect("promoted slot");
        assert_eq!(promoted.journal.authorization_decision, Some(allowed));
        promoted.finalize().expect("finalize promoted slot");
    }

    #[test]
    fn slot_rejects_unprotected_store_and_substituted_child_binding() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        assert!(matches!(
            ActiveSlot::begin(
                temporary.path(),
                owner,
                temporary.path(),
                "invocation-123",
                identity('a').as_str(),
                identity('b').as_str(),
                working_directory(),
            ),
            Err(ActiveSlotError::StoreInvalid)
        ));

        let mut journal = ActiveSlotJournalV1 {
            schema_version: 1,
            identity: String::new(),
            stage: ActiveSlotStage::ChildPrepared,
            invocation_id: "invocation-123".into(),
            principal_mapping_identity: identity('a'),
            request_identity: identity('b'),
            working_directory: working_directory(),
            child: Some(LauncherChildProcessV1 {
                schema_version: 1,
                identity: String::new(),
                invocation_id: "invocation-123".into(),
                request_identity: identity('b'),
                pid: 4242,
                process_start_time_identity: identity('c'),
                ota_binary_identity: identity('d'),
                principal_mapping_identity: identity('e'),
                working_directory_identity: identity('f'),
            }),
            scope: None,
            authorization_decision: None,
            lease_consumption_intent: None,
            lease_consumption: None,
            execution_completion: None,
        };
        let child = journal.child.as_mut().expect("child");
        child.identity = launcher_child_process_identity(child).expect("child identity");
        assert_eq!(
            active_slot_identity(&journal),
            Err(ActiveSlotError::InvalidJournal)
        );
    }

    #[test]
    fn child_bearing_temporary_journal_is_promoted_for_recovery() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        let mapping_identity = identity('a');
        let request_identity = identity('b');
        let slot = ActiveSlot::begin(
            temporary.path(),
            owner,
            temporary.path(),
            "invocation-crash",
            mapping_identity.as_str(),
            request_identity.as_str(),
            working_directory(),
        )
        .expect("begin slot");
        let canonical_path = slot.path.clone();
        let mut recovered = load_journal(&canonical_path).expect("intent journal");
        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: recovered.invocation_id.clone(),
            request_identity: recovered.request_identity.clone(),
            pid: 4242,
            process_start_time_identity: identity('c'),
            ota_binary_identity: identity('d'),
            principal_mapping_identity: recovered.principal_mapping_identity.clone(),
            working_directory_identity: recovered.working_directory.identity.clone(),
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        recovered.stage = ActiveSlotStage::ChildPrepared;
        recovered.child = Some(child.clone());
        recovered.identity = active_slot_identity(&recovered).expect("recovery identity");
        let temporary_path = temporary.path().join(".invocation-crash.tmp");
        write_new(&temporary_path, &recovered).expect("temporary child journal");
        sync_directory(temporary.path()).expect("temporary journal sync");
        drop(slot);

        let mut slots = ActiveSlot::load_all(temporary.path(), owner, temporary.path())
            .expect("load promoted child journal");
        assert!(!temporary_path.exists());
        assert_eq!(slots.len(), 1);
        let promoted = slots.pop().expect("promoted slot");
        assert_eq!(promoted.child(), Some(&child));
        promoted.finalize().expect("finalize promoted slot");
    }

    #[test]
    fn incomplete_scope_temporary_journal_recovers_from_canonical_child() {
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let owner = unsafe { libc::geteuid() };
        let mapping = identity('a');
        let request = identity('b');
        let journal = prepared_journal("invocation-partial", mapping.as_str(), request.as_str());
        let mut slot = ActiveSlot::begin(
            temporary.path(),
            owner,
            temporary.path(),
            journal.invocation_id.as_str(),
            mapping.as_str(),
            request.as_str(),
            journal.working_directory.clone(),
        )
        .expect("begin slot");
        slot.record_child(journal.child.clone().expect("prepared child"))
            .expect("record child");
        let incomplete = temporary.path().join(".invocation-partial.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&incomplete).expect("incomplete journal");
        file.write_all(b"{\"schema_version\":1")
            .and_then(|_| file.sync_all())
            .expect("persist incomplete journal");
        sync_directory(temporary.path()).expect("sync incomplete journal");
        drop(file);
        drop(slot);

        let slots = ActiveSlot::load_all(temporary.path(), owner, temporary.path())
            .expect("recover canonical child journal");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].journal.stage, ActiveSlotStage::ChildPrepared);
        assert!(!incomplete.exists());
        slots
            .into_iter()
            .next()
            .expect("recovered slot")
            .finalize()
            .expect("cleanup recovered slot");
    }

    #[test]
    fn unmatched_contradictory_and_duplicate_temporary_journals_refuse() {
        let owner = unsafe { libc::geteuid() };
        let mapping = identity('a');
        let request = identity('b');

        let unmatched = tempdir().expect("unmatched directory");
        fs::set_permissions(unmatched.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let unmatched_path = unmatched.path().join(".invocation-unmatched.tmp");
        write_new(
            &unmatched_path,
            &prepared_journal("invocation-unmatched", mapping.as_str(), request.as_str()),
        )
        .expect("unmatched temporary journal");
        assert!(matches!(
            ActiveSlot::load_all(unmatched.path(), owner, unmatched.path()),
            Err(ActiveSlotError::InvalidJournal)
        ));
        assert!(unmatched_path.exists());

        let contradictory = tempdir().expect("contradictory directory");
        fs::set_permissions(contradictory.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let canonical = ActiveSlot::begin(
            contradictory.path(),
            owner,
            contradictory.path(),
            "invocation-canonical",
            mapping.as_str(),
            request.as_str(),
            working_directory(),
        )
        .expect("canonical intent");
        let contradictory_path = contradictory.path().join(".invocation-other.tmp");
        write_new(
            &contradictory_path,
            &prepared_journal("invocation-other", mapping.as_str(), request.as_str()),
        )
        .expect("contradictory temporary journal");
        drop(canonical);
        assert!(matches!(
            ActiveSlot::load_all(contradictory.path(), owner, contradictory.path()),
            Err(ActiveSlotError::InvalidJournal)
        ));
        assert!(contradictory_path.exists());

        let duplicate = tempdir().expect("duplicate directory");
        fs::set_permissions(duplicate.path(), fs::Permissions::from_mode(0o700))
            .expect("permissions");
        let canonical = ActiveSlot::begin(
            duplicate.path(),
            owner,
            duplicate.path(),
            "invocation-primary",
            mapping.as_str(),
            request.as_str(),
            working_directory(),
        )
        .expect("duplicate canonical intent");
        for invocation in ["invocation-primary", "invocation-duplicate"] {
            write_new(
                &duplicate.path().join(format!(".{invocation}.tmp")),
                &prepared_journal(invocation, mapping.as_str(), request.as_str()),
            )
            .expect("duplicate temporary journal");
        }
        drop(canonical);
        assert!(matches!(
            ActiveSlot::load_all(duplicate.path(), owner, duplicate.path()),
            Err(ActiveSlotError::InvalidJournal)
        ));
        assert_eq!(
            fs::read_dir(duplicate.path())
                .expect("duplicate entries")
                .count(),
            3
        );
    }
}
