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

//! Root-only controller for independently administered systemd crash/reboot pressure.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use clap::{Parser, Subcommand, ValueEnum};
    use ota_authority_launcher::systemd_client::{
        InvocationRequest, InvocationResult, recover_invocation_with_observer,
    };
    use ota_authority_protocol::{
        LAUNCHER_INVOCATION_REQUEST, LauncherInvocationRequestV1,
        SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, launcher_invocation_request_identity,
        validate_launcher_invocation_request_v1,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    const STATE_ROOT: &str = "/var/lib/ota/authority-admin-pressure";
    const STATE_PATH: &str = "/var/lib/ota/authority-admin-pressure/pending.json";
    const EVIDENCE_ROOT: &str = "/usr/share/ota/authority-launcher/recovery-evidence";
    const RUNNER_SERVICE: &str = "ota-authority-pressure-runner.service";
    const OTA_BINARY: &str = "/usr/lib/ota-authority/bin/ota";
    const STATE_IDENTITY_DOMAIN: &[u8] = b"ota.authority-launcher.admin-recovery-state.v1\0";
    const EVIDENCE_IDENTITY_DOMAIN: &[u8] = b"ota.authority-launcher.admin-recovery-evidence.v1\0";
    const INSTALLATION_EVIDENCE_IDENTITY_DOMAIN: &[u8] =
        b"ota.authority-launcher.public-installation-evidence.v1\0";
    const PROVISIONING_OBSERVATION_IDENTITY_DOMAIN: &[u8] =
        b"ota.authority-launcher.prepared-provisioning-observation.v1\0";
    const ACTIVE_SLOT_IDENTITY_DOMAIN: &[u8] = b"ota.authority-launcher.active-slot.v1\0";
    const FINALIZATION_JOURNAL_IDENTITY_DOMAIN: &[u8] =
        b"ota.authority-launcher.finalization-journal.v1\0";

    #[derive(Debug, Parser)]
    #[command(name = "ota-authority-systemd-recovery-controller", version, about)]
    pub struct Cli {
        #[command(subcommand)]
        command: ControllerCommand,
    }

    #[derive(Debug, Subcommand)]
    enum ControllerCommand {
        Arm {
            #[arg(long, value_enum)]
            fault: FaultPoint,
            #[arg(long)]
            authority_id: String,
            #[arg(long)]
            repository: PathBuf,
            #[arg(long)]
            job_user: String,
            #[arg(long)]
            expected_execution_count: u64,
            #[arg(long)]
            expected_archive_count: u64,
            #[arg(last = true, required = true)]
            ota_arguments: Vec<String>,
        },
        Reboot,
        Verify,
        AbortPrepared,
        Status,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
    #[serde(rename_all = "snake_case")]
    enum FaultPoint {
        ExecutionCompletion,
        FinalizationIntent,
        TerminalRecorded,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum ControllerStage {
        Prepared,
        FaultObserved,
        RecoveryObserved,
    }

    impl FaultPoint {
        fn marker_path(self) -> &'static str {
            match self {
                Self::ExecutionCompletion => {
                    "/run/ota/authority-launcher-pressure-exit-after-execution-completion"
                }
                Self::FinalizationIntent => {
                    "/run/ota/authority-launcher-pressure-exit-after-finalization-intent"
                }
                Self::TerminalRecorded => {
                    "/run/ota/authority-launcher-pressure-exit-after-terminal-recorded"
                }
            }
        }

        fn label(self) -> &'static str {
            match self {
                Self::ExecutionCompletion => "execution-completion",
                Self::FinalizationIntent => "finalization-intent",
                Self::TerminalRecorded => "terminal-recorded",
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryStateV1 {
        schema_version: u32,
        identity: String,
        previous_identity: Option<String>,
        prepared_state_identity: String,
        stage: ControllerStage,
        fault: FaultPoint,
        authority_id: String,
        repository: PathBuf,
        job_user: String,
        job_uid: u32,
        job_gid: u32,
        execution_uid: u32,
        ota_arguments: Vec<String>,
        launcher_request_identity: String,
        installation_evidence_identity: String,
        controller_binary_identity: String,
        protocol_source_revision: String,
        core_source_revision: String,
        launcher_source_revision: String,
        boot_id_before: String,
        armed_at: String,
        expected_execution_count: u64,
        expected_archive_count: u64,
        repository_manifest_before: String,
        retained_record_kind: String,
        retained_record_stage: String,
        retained_record_identity: String,
        invocation_id: String,
        receipt_archive_identity: String,
        crossing_transaction_identity: String,
        retained_active_records: u64,
        retained_finalization_records: u64,
        recovered_result: Option<InvocationResult>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryEvidenceV1 {
        schema_version: u32,
        identity: String,
        state_identity: String,
        prepared_state_identity: String,
        fault_observed_state_identity: String,
        fault: FaultPoint,
        launcher_request_identity: String,
        installation_evidence_identity: String,
        controller_binary_identity: String,
        protocol_source_revision: String,
        core_source_revision: String,
        launcher_source_revision: String,
        boot_id_before: String,
        boot_id_after: String,
        verified_at: String,
        execution_count: u64,
        archive_count: u64,
        invalid_archive_count: u64,
        repository_manifest_before: String,
        repository_manifest_after: String,
        retained_record_kind: String,
        retained_record_stage: String,
        retained_record_identity: String,
        invocation_id: String,
        receipt_archive_identity: String,
        crossing_transaction_identity: String,
        terminal_stage: String,
        terminal_outcome: String,
        child_reaped_or_absent: bool,
        scope_removed: bool,
        cgroup_empty_or_absent: bool,
        active_slot_removed: bool,
        residual_active_records: u64,
        residual_finalization_records: u64,
        residual_scope_units: Vec<String>,
        private_material_included: bool,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ChildInvocationResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<InvocationResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_reason: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct HistorySummary {
        archive_count: u64,
        invalid_archive_count: u64,
    }

    #[derive(Debug, Deserialize)]
    struct HistoryOutput {
        ok: bool,
        history_source: String,
        completeness_posture: String,
        summary: HistorySummary,
        archives: Vec<HistoryArchive>,
    }

    #[derive(Debug, Deserialize)]
    struct HistoryArchive {
        archive_identity: String,
    }

    struct InstallationEvidenceReference {
        identity: String,
        protocol_source_revision: String,
        core_source_revision: String,
        launcher_source_revision: String,
        job_uid: u32,
        execution_uid: u32,
    }

    struct RetainedCheckpoint {
        kind: String,
        stage: String,
        identity: String,
        invocation_id: String,
        receipt_archive_identity: String,
        crossing_transaction_identity: String,
    }

    pub fn main() -> Result<(), String> {
        require_root()?;
        match Cli::parse().command {
            ControllerCommand::Arm {
                fault,
                authority_id,
                repository,
                job_user,
                expected_execution_count,
                expected_archive_count,
                ota_arguments,
            } => arm(
                fault,
                authority_id,
                repository,
                job_user,
                expected_execution_count,
                expected_archive_count,
                ota_arguments,
            ),
            ControllerCommand::Reboot => reboot(),
            ControllerCommand::Verify => verify(),
            ControllerCommand::AbortPrepared => abort_prepared(),
            ControllerCommand::Status => status(),
        }
    }

    fn arm(
        fault: FaultPoint,
        authority_id: String,
        repository: PathBuf,
        job_user: String,
        expected_execution_count: u64,
        expected_archive_count: u64,
        ota_arguments: Vec<String>,
    ) -> Result<(), String> {
        ensure_runner_stopped()?;
        require_absent(Path::new(STATE_PATH), "pending recovery state")?;
        if expected_execution_count == 0
            || expected_archive_count == 0
            || expected_execution_count != expected_archive_count
        {
            return Err(String::from(
                "expected execution and archive counts must be the same positive value",
            ));
        }
        let repository = repository
            .canonicalize()
            .map_err(|_| String::from("the pressure repository is unavailable"))?;
        let (job_uid, job_gid) = account(job_user.as_str())?;
        let launcher_request_identity = request_identity(
            authority_id.as_str(),
            repository.as_path(),
            ota_arguments.as_slice(),
        )?;
        let installation = installation_evidence_reference()?;
        if installation.job_uid != job_uid || installation.execution_uid == job_uid {
            return Err(String::from(
                "the configured job principal does not match installation evidence",
            ));
        }
        require_no_principal_processes(&[installation.job_uid, installation.execution_uid])?;
        let controller_binary_identity = file_identity(
            std::env::current_exe()
                .map_err(|_| String::from("controller executable identity is unavailable"))?
                .as_path(),
        )?;
        let repository_manifest_before = repository_manifest(repository.as_path())?;
        let mut state = RecoveryStateV1 {
            schema_version: 1,
            identity: String::new(),
            previous_identity: None,
            prepared_state_identity: String::new(),
            stage: ControllerStage::Prepared,
            fault,
            authority_id,
            repository,
            job_user,
            job_uid,
            job_gid,
            execution_uid: installation.execution_uid,
            ota_arguments,
            launcher_request_identity,
            installation_evidence_identity: installation.identity,
            controller_binary_identity,
            protocol_source_revision: installation.protocol_source_revision,
            core_source_revision: installation.core_source_revision,
            launcher_source_revision: installation.launcher_source_revision,
            boot_id_before: boot_id()?,
            armed_at: now()?,
            expected_execution_count,
            expected_archive_count,
            repository_manifest_before,
            retained_record_kind: String::new(),
            retained_record_stage: String::new(),
            retained_record_identity: String::new(),
            invocation_id: String::new(),
            receipt_archive_identity: String::new(),
            crossing_transaction_identity: String::new(),
            retained_active_records: 0,
            retained_finalization_records: 0,
            recovered_result: None,
        };
        state.identity = semantic_identity(STATE_IDENTITY_DOMAIN, &state)?;
        write_protected_json(Path::new(STATE_PATH), &state, 0o600, false)?;
        create_root_marker(Path::new(fault.marker_path()))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "stage": "fault_prepared_runner_invocation_required",
                "fault": fault,
                "state_identity": state.identity,
                "launcher_request_identity": state.launcher_request_identity,
            }))
            .map_err(|_| String::from("failed to encode controller output"))?
        );
        Ok(())
    }

    fn reboot() -> Result<(), String> {
        let mut state = load_state()?;
        if state.stage == ControllerStage::Prepared {
            state = observe_fault(state)?;
        }
        if state.stage != ControllerStage::FaultObserved {
            return Err(String::from("the controller fault state is incomplete"));
        }
        require_no_principal_processes(&[state.job_uid, state.execution_uid])?;
        if boot_id()? != state.boot_id_before {
            return Err(String::from(
                "the pending recovery state already crossed a reboot",
            ));
        }
        ensure_runner_stopped()?;
        let status = Command::new("/usr/bin/systemctl")
            .arg("reboot")
            .status()
            .map_err(|_| String::from("failed to request the administrator-owned reboot"))?;
        if status.success() {
            Ok(())
        } else {
            Err(String::from("the administrator-owned reboot was refused"))
        }
    }

    fn abort_prepared() -> Result<(), String> {
        ensure_runner_stopped()?;
        let state = load_state()?;
        if state.stage != ControllerStage::Prepared
            || state.previous_identity.is_some()
            || boot_id()? != state.boot_id_before
        {
            return Err(String::from(
                "only a same-boot prepared recovery attempt can be aborted",
            ));
        }
        require_no_principal_processes(&[state.job_uid, state.execution_uid])?;
        if regular_file_count(Path::new("/var/lib/ota/authority-launcher/active"))? != 0
            || regular_file_count(Path::new("/var/lib/ota/authority-launcher/finalization"))? != 0
            || !residual_scope_units()?.is_empty()
            || execution_count(state.repository.as_path())?
                != state.expected_execution_count.saturating_sub(1)
            || repository_manifest(state.repository.as_path())? != state.repository_manifest_before
        {
            return Err(String::from(
                "the prepared recovery attempt may have created execution state and cannot be aborted",
            ));
        }
        remove_unconsumed_marker_if_present(Path::new(state.fault.marker_path()))?;
        fs::remove_file(STATE_PATH)
            .map_err(|_| String::from("failed to remove aborted recovery state"))?;
        fsync_directory(Path::new(STATE_ROOT))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "stage": "prepared_attempt_aborted",
                "fault": state.fault,
                "state_identity": state.identity,
            }))
            .map_err(|_| String::from("failed to encode abort evidence"))?
        );
        Ok(())
    }

    fn verify() -> Result<(), String> {
        ensure_runner_stopped()?;
        let mut state = load_state()?;
        if state.stage == ControllerStage::Prepared {
            state = observe_fault(state)?;
        }
        if !matches!(
            state.stage,
            ControllerStage::FaultObserved | ControllerStage::RecoveryObserved
        ) {
            return Err(String::from("the controller fault state is incomplete"));
        }
        require_no_principal_processes(&[state.job_uid, state.execution_uid])?;
        let boot_id_after = boot_id()?;
        if boot_id_after == state.boot_id_before {
            return Err(String::from("host reboot was not observed"));
        }
        let installation = installation_evidence_reference()?;
        if installation.identity != state.installation_evidence_identity
            || installation.protocol_source_revision != state.protocol_source_revision
            || installation.core_source_revision != state.core_source_revision
            || installation.launcher_source_revision != state.launcher_source_revision
            || file_identity(
                std::env::current_exe()
                    .map_err(|_| String::from("controller executable identity is unavailable"))?
                    .as_path(),
            )? != state.controller_binary_identity
        {
            return Err(String::from("installation evidence changed across reboot"));
        }
        let observed_request_identity = request_identity(
            state.authority_id.as_str(),
            state.repository.as_path(),
            state.ota_arguments.as_slice(),
        )?;
        if observed_request_identity != state.launcher_request_identity {
            return Err(String::from("the frozen recovery invocation changed"));
        }
        if let Some(evidence) = existing_completed_evidence(&state, boot_id_after.as_str())? {
            return complete_state_and_print(&evidence);
        }
        let residual_finalization_before =
            regular_file_count(Path::new("/var/lib/ota/authority-launcher/finalization"))?;
        let result = if state.stage == ControllerStage::RecoveryObserved
            && residual_finalization_before == 0
        {
            state
                .recovered_result
                .clone()
                .ok_or_else(|| String::from("the recovered terminal state is incomplete"))?
        } else {
            recover_as_principal(&mut state)?
        };
        let finalization = result
            .terminal
            .finalization
            .as_ref()
            .ok_or_else(|| String::from("the recovery terminal omitted finalization"))?;
        let completion = &finalization.completion;
        if !result.ok
            || result.output_complete
            || result.request_identity != state.launcher_request_identity
            || completion.invocation_id != state.invocation_id
            || completion.receipt_archive_identity.as_deref()
                != Some(state.receipt_archive_identity.as_str())
            || completion.crossing_transaction_identity != state.crossing_transaction_identity
        {
            return Err(String::from(
                "the recovered production-client result is invalid",
            ));
        }
        let execution_count = execution_count(state.repository.as_path())?;
        if execution_count != state.expected_execution_count {
            return Err(String::from(
                "selected execution count changed during recovery",
            ));
        }
        let history = protected_history(state.job_uid, state.job_gid, state.repository.as_path())?;
        if !history.ok
            || history.history_source != "systemd_protected_launcher"
            || history.completeness_posture != "complete_selected_catalog_snapshot"
            || history.summary.archive_count != state.expected_archive_count
            || history.summary.invalid_archive_count != 0
            || !history
                .archives
                .iter()
                .any(|archive| archive.archive_identity == state.receipt_archive_identity)
        {
            return Err(String::from(
                "protected history did not reconcile after reboot",
            ));
        }
        let repository_manifest_after = repository_manifest(state.repository.as_path())?;
        if repository_manifest_after != state.repository_manifest_before {
            return Err(String::from("repository truth changed during recovery"));
        }
        let residual_active_records =
            regular_file_count(Path::new("/var/lib/ota/authority-launcher/active"))?;
        let residual_finalization_records =
            regular_file_count(Path::new("/var/lib/ota/authority-launcher/finalization"))?;
        let residual_scope_units = residual_scope_units()?;
        if residual_active_records != 0
            || residual_finalization_records != 0
            || !residual_scope_units.is_empty()
        {
            return Err(String::from(
                "protected recovery left residual execution state",
            ));
        }

        let terminal_stage = serde_json::to_value(result.terminal.stage)
            .ok()
            .and_then(|value| value.as_str().map(String::from))
            .ok_or_else(|| String::from("recovery terminal stage is unavailable"))?;
        let terminal_outcome = serde_json::to_value(result.terminal.outcome)
            .ok()
            .and_then(|value| value.as_str().map(String::from))
            .ok_or_else(|| String::from("recovery terminal outcome is unavailable"))?;
        if terminal_stage != "selected_execution_completed_boundary_removed"
            || terminal_outcome != "completed"
            || result.terminal.exit_code != Some(0)
        {
            return Err(String::from("the recovered terminal posture is invalid"));
        }

        let mut evidence = RecoveryEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            state_identity: state.identity.clone(),
            prepared_state_identity: state.prepared_state_identity.clone(),
            fault_observed_state_identity: state
                .previous_identity
                .clone()
                .ok_or_else(|| String::from("fault-observed recovery identity is unavailable"))?,
            fault: state.fault,
            launcher_request_identity: state.launcher_request_identity.clone(),
            installation_evidence_identity: state.installation_evidence_identity.clone(),
            controller_binary_identity: state.controller_binary_identity,
            protocol_source_revision: state.protocol_source_revision,
            core_source_revision: state.core_source_revision,
            launcher_source_revision: state.launcher_source_revision,
            boot_id_before: state.boot_id_before,
            boot_id_after,
            verified_at: now()?,
            execution_count,
            archive_count: history.summary.archive_count,
            invalid_archive_count: history.summary.invalid_archive_count,
            repository_manifest_before: state.repository_manifest_before,
            repository_manifest_after,
            retained_record_kind: state.retained_record_kind,
            retained_record_stage: state.retained_record_stage,
            retained_record_identity: state.retained_record_identity,
            invocation_id: state.invocation_id,
            receipt_archive_identity: state.receipt_archive_identity,
            crossing_transaction_identity: state.crossing_transaction_identity,
            terminal_stage,
            terminal_outcome,
            child_reaped_or_absent: finalization.child_reaped
                || finalization.child_absent.unwrap_or(false),
            scope_removed: finalization.scope_removed,
            cgroup_empty_or_absent: finalization.cgroup_empty_or_absent,
            active_slot_removed: finalization.active_slot_removed,
            residual_active_records,
            residual_finalization_records,
            residual_scope_units,
            private_material_included: false,
        };
        if !evidence.child_reaped_or_absent
            || !evidence.scope_removed
            || !evidence.cgroup_empty_or_absent
            || !evidence.active_slot_removed
        {
            return Err(String::from("terminal cleanup evidence is incomplete"));
        }
        evidence.identity = semantic_identity(EVIDENCE_IDENTITY_DOMAIN, &evidence)?;
        let evidence_path = completed_evidence_path(state.fault);
        write_protected_json(evidence_path.as_path(), &evidence, 0o644, true)?;
        complete_state_and_print(&evidence)
    }

    fn completed_evidence_path(fault: FaultPoint) -> PathBuf {
        Path::new(EVIDENCE_ROOT).join(format!("{}.json", fault.label()))
    }

    fn existing_completed_evidence(
        state: &RecoveryStateV1,
        boot_id_after: &str,
    ) -> Result<Option<RecoveryEvidenceV1>, String> {
        let path = completed_evidence_path(state.fault);
        match fs::symlink_metadata(path.as_path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(String::from("completed recovery evidence is unavailable")),
            Ok(metadata) => {
                if metadata.permissions().mode() & 0o7777 != 0o644 {
                    return Err(String::from("completed recovery evidence mode is invalid"));
                }
                let evidence: RecoveryEvidenceV1 = read_protected_json(path.as_path())?;
                if semantic_identity(EVIDENCE_IDENTITY_DOMAIN, &evidence)? != evidence.identity
                    || evidence.state_identity != state.identity
                    || evidence.prepared_state_identity != state.prepared_state_identity
                    || evidence.fault_observed_state_identity
                        != state.previous_identity.as_deref().unwrap_or_default()
                    || evidence.fault != state.fault
                    || evidence.launcher_request_identity != state.launcher_request_identity
                    || evidence.installation_evidence_identity
                        != state.installation_evidence_identity
                    || evidence.controller_binary_identity != state.controller_binary_identity
                    || evidence.protocol_source_revision != state.protocol_source_revision
                    || evidence.core_source_revision != state.core_source_revision
                    || evidence.launcher_source_revision != state.launcher_source_revision
                    || evidence.boot_id_before != state.boot_id_before
                    || evidence.boot_id_after != boot_id_after
                    || evidence.execution_count != state.expected_execution_count
                    || evidence.archive_count != state.expected_archive_count
                    || evidence.invalid_archive_count != 0
                    || evidence.repository_manifest_before != state.repository_manifest_before
                    || evidence.repository_manifest_after != state.repository_manifest_before
                    || evidence.retained_record_kind != state.retained_record_kind
                    || evidence.retained_record_stage != state.retained_record_stage
                    || evidence.retained_record_identity != state.retained_record_identity
                    || evidence.invocation_id != state.invocation_id
                    || evidence.receipt_archive_identity != state.receipt_archive_identity
                    || evidence.crossing_transaction_identity != state.crossing_transaction_identity
                    || evidence.terminal_stage != "selected_execution_completed_boundary_removed"
                    || evidence.terminal_outcome != "completed"
                    || !evidence.child_reaped_or_absent
                    || !evidence.scope_removed
                    || !evidence.cgroup_empty_or_absent
                    || !evidence.active_slot_removed
                    || evidence.residual_active_records != 0
                    || evidence.residual_finalization_records != 0
                    || !evidence.residual_scope_units.is_empty()
                    || evidence.private_material_included
                {
                    return Err(String::from("completed recovery evidence is inconsistent"));
                }
                let history =
                    protected_history(state.job_uid, state.job_gid, state.repository.as_path())?;
                if execution_count(state.repository.as_path())? != state.expected_execution_count
                    || repository_manifest(state.repository.as_path())?
                        != state.repository_manifest_before
                    || regular_file_count(Path::new("/var/lib/ota/authority-launcher/active"))? != 0
                    || regular_file_count(Path::new(
                        "/var/lib/ota/authority-launcher/finalization",
                    ))? != 0
                    || !residual_scope_units()?.is_empty()
                    || !history.ok
                    || history.summary.archive_count != state.expected_archive_count
                    || history.summary.invalid_archive_count != 0
                    || !history
                        .archives
                        .iter()
                        .any(|archive| archive.archive_identity == state.receipt_archive_identity)
                {
                    return Err(String::from(
                        "completed recovery evidence no longer matches live protected state",
                    ));
                }
                Ok(Some(evidence))
            }
        }
    }

    fn complete_state_and_print(evidence: &RecoveryEvidenceV1) -> Result<(), String> {
        fs::remove_file(STATE_PATH)
            .map_err(|_| String::from("failed to remove completed recovery state"))?;
        fsync_directory(Path::new(STATE_ROOT))?;
        println!(
            "{}",
            serde_json::to_string_pretty(evidence)
                .map_err(|_| String::from("failed to encode recovery evidence"))?
        );
        Ok(())
    }

    fn status() -> Result<(), String> {
        match fs::symlink_metadata(STATE_PATH) {
            Ok(_) => println!(
                "{}",
                serde_json::to_string_pretty(&load_state()?)
                    .map_err(|_| String::from("failed to encode pending recovery state"))?
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("{{\n  \"ok\": true,\n  \"pending\": false\n}}")
            }
            Err(_) => return Err(String::from("pending recovery state is unavailable")),
        }
        Ok(())
    }

    fn enter_exact_principal(uid: u32, gid: u32) -> bool {
        let null = unsafe {
            libc::open(
                c"/dev/null".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if null <= libc::STDERR_FILENO {
            if null >= 0 {
                unsafe { libc::close(null) };
            }
            return false;
        }
        let mut null_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let null_valid = unsafe {
            libc::fstat(null, null_stat.as_mut_ptr()) == 0
                && null_stat.assume_init_ref().st_mode & libc::S_IFMT == libc::S_IFCHR
        };
        let stdout_redirected =
            null_valid && unsafe { libc::dup2(null, libc::STDOUT_FILENO) } == libc::STDOUT_FILENO;
        let stderr_redirected = stdout_redirected
            && unsafe { libc::dup2(null, libc::STDERR_FILENO) } == libc::STDERR_FILENO;
        let descriptors_match = stderr_redirected
            && descriptor_matches(libc::STDOUT_FILENO, unsafe { null_stat.assume_init_ref() })
            && descriptor_matches(libc::STDERR_FILENO, unsafe { null_stat.assume_init_ref() });
        let null_closed = unsafe { libc::close(null) } == 0;
        if !descriptors_match || !null_closed || unsafe { libc::clearenv() } != 0 {
            return false;
        }
        let changed = unsafe {
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setgid(gid) == 0
                && libc::setuid(uid) == 0
                && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
        };
        changed
            && unsafe { libc::getuid() } == uid
            && unsafe { libc::geteuid() } == uid
            && unsafe { libc::getgid() } == gid
            && unsafe { libc::getegid() } == gid
            && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0
            && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1
            && std::env::vars_os().next().is_none()
    }

    fn descriptor_matches(descriptor: i32, expected: &libc::stat) -> bool {
        let mut observed = std::mem::MaybeUninit::<libc::stat>::uninit();
        (unsafe { libc::fstat(descriptor, observed.as_mut_ptr()) == 0 }) && {
            let observed = unsafe { observed.assume_init_ref() };
            observed.st_dev == expected.st_dev
                && observed.st_ino == expected.st_ino
                && observed.st_rdev == expected.st_rdev
        }
    }

    fn recover_as_principal(state: &mut RecoveryStateV1) -> Result<InvocationResult, String> {
        let mut descriptors = [0_i32; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                descriptors.as_mut_ptr(),
            )
        } != 0
        {
            return Err(String::from(
                "failed to create the recovery observation channel",
            ));
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(String::from(
                "failed to fork the constrained recovery client",
            ));
        }
        if pid == 0 {
            unsafe { libc::close(descriptors[0]) };
            let mut channel = unsafe { UnixStream::from_raw_fd(descriptors[1]) };
            let mut observation_sent = false;
            let result = if enter_exact_principal(state.job_uid, state.job_gid) {
                recover_invocation_with_observer(
                    InvocationRequest {
                        authority_id: state.authority_id.clone(),
                        repository: state.repository.clone(),
                        ota_arguments: state.ota_arguments.clone(),
                    },
                    |result| {
                        let observation = ChildInvocationResult {
                            ok: true,
                            result: Some(result.clone()),
                            error_reason: None,
                        };
                        serde_json::to_writer(&mut channel, &observation)
                            .and_then(|()| channel.flush().map_err(serde_json::Error::io))
                            .map_err(|_| {
                                ota_authority_launcher::systemd_client::ClientError::LocalBoundary
                            })?;
                        channel.shutdown(Shutdown::Write).map_err(|_| {
                            ota_authority_launcher::systemd_client::ClientError::LocalBoundary
                        })?;
                        observation_sent = true;
                        let mut acknowledgement = [0_u8; 1];
                        channel.read_exact(&mut acknowledgement).map_err(|_| {
                            ota_authority_launcher::systemd_client::ClientError::LocalBoundary
                        })?;
                        if acknowledgement != [0xA5] {
                            return Err(
                                ota_authority_launcher::systemd_client::ClientError::LocalBoundary,
                            );
                        }
                        Ok(())
                    },
                )
            } else {
                Err(ota_authority_launcher::systemd_client::ClientError::LocalBoundary)
            };
            if result.is_err() && !observation_sent {
                let observation = ChildInvocationResult {
                    ok: false,
                    result: None,
                    error_reason: Some(
                        result
                            .as_ref()
                            .expect_err("failed recovery must include an error")
                            .reason_code()
                            .into(),
                    ),
                };
                let _ = serde_json::to_writer(&mut channel, &observation);
                let _ = channel.flush();
                let _ = channel.shutdown(Shutdown::Write);
            }
            unsafe { libc::_exit(u8::from(result.is_err()).into()) }
        }

        unsafe { libc::close(descriptors[1]) };
        let mut channel = unsafe { UnixStream::from_raw_fd(descriptors[0]) };
        let mut encoded = Vec::new();
        std::io::Read::by_ref(&mut channel)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| String::from("failed to read the recovery observation"))?;
        if encoded.len() > 1024 * 1024 {
            return Err(String::from("the recovery observation is too large"));
        }
        let observation: ChildInvocationResult = serde_json::from_slice(encoded.as_slice())
            .map_err(|_| String::from("the recovery observation is invalid"))?;
        let result = observation.result.ok_or_else(|| {
            format!(
                "the recovery client refused before terminal observation: {}",
                observation.error_reason.as_deref().unwrap_or("unknown")
            )
        })?;
        validate_recovered_result(state, &result)?;
        record_recovery_observed(state, &result)?;
        channel
            .write_all(&[0xA5])
            .and_then(|()| channel.flush())
            .map_err(|_| String::from("failed to acknowledge durable recovery observation"))?;
        let mut status = 0_i32;
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            return Err(String::from(
                "terminal acknowledgement remains uncertain after durable recovery observation",
            ));
        }
        Ok(result)
    }

    fn validate_recovered_result(
        state: &RecoveryStateV1,
        result: &InvocationResult,
    ) -> Result<(), String> {
        let completion = result
            .terminal
            .finalization
            .as_ref()
            .ok_or_else(|| String::from("the recovery terminal omitted finalization"))?
            .completion
            .clone();
        if !result.ok
            || result.output_complete
            || result.request_identity != state.launcher_request_identity
            || completion.invocation_id != state.invocation_id
            || completion.receipt_archive_identity.as_deref()
                != Some(state.receipt_archive_identity.as_str())
            || completion.crossing_transaction_identity != state.crossing_transaction_identity
        {
            return Err(String::from(
                "the recovered production-client result is invalid",
            ));
        }
        Ok(())
    }

    fn record_recovery_observed(
        state: &mut RecoveryStateV1,
        result: &InvocationResult,
    ) -> Result<(), String> {
        if state.stage == ControllerStage::RecoveryObserved {
            let persisted = state
                .recovered_result
                .as_ref()
                .ok_or_else(|| String::from("persisted recovery observation is unavailable"))?;
            let persisted = serde_jcs::to_vec(persisted)
                .map_err(|_| String::from("persisted recovery observation is invalid"))?;
            let observed = serde_jcs::to_vec(result)
                .map_err(|_| String::from("replayed recovery observation is invalid"))?;
            if persisted != observed {
                return Err(String::from("replayed recovery terminal changed"));
            }
            return Ok(());
        }
        if state.stage != ControllerStage::FaultObserved {
            return Err(String::from("recovery observation state is invalid"));
        }
        let previous_identity = state.identity.clone();
        state.previous_identity = Some(previous_identity);
        state.stage = ControllerStage::RecoveryObserved;
        state.recovered_result = Some(result.clone());
        state.identity = semantic_identity(STATE_IDENTITY_DOMAIN, state)?;
        replace_protected_json(Path::new(STATE_PATH), state, 0o600)
    }

    fn protected_history(uid: u32, gid: u32, repository: &Path) -> Result<HistoryOutput, String> {
        let mut command = Command::new(OTA_BINARY);
        command.current_dir(repository).args([
            "receipt",
            "--history",
            "--source",
            "systemd_protected_launcher",
            "--json",
        ]);
        configure_exact_principal(&mut command, uid, gid);
        command.env_clear();
        let output = command
            .output()
            .map_err(|_| String::from("failed to query protected history"))?;
        if !output.status.success() {
            return Err(String::from("protected history refused after reboot"));
        }
        serde_json::from_slice(output.stdout.as_slice())
            .map_err(|_| String::from("protected history output is invalid"))
    }

    fn configure_exact_principal(command: &mut Command, uid: u32, gid: u32) {
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn request_identity(
        authority_id: &str,
        repository: &Path,
        ota_arguments: &[String],
    ) -> Result<String, String> {
        let request = LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: authority_id.into(),
            ota_arguments: ota_arguments.to_vec(),
            repository_path: repository.to_string_lossy().into_owned(),
        };
        validate_launcher_invocation_request_v1(&request)
            .map_err(|_| String::from("the frozen launcher request is invalid"))?;
        launcher_invocation_request_identity(&request)
            .map_err(|_| String::from("the frozen launcher request identity is unavailable"))
    }

    fn account(name: &str) -> Result<(u32, u32), String> {
        let name = CString::new(name).map_err(|_| String::from("the job user is invalid"))?;
        let account = unsafe { libc::getpwnam(name.as_ptr()) };
        if account.is_null() {
            return Err(String::from("the configured job user is unavailable"));
        }
        let account = unsafe { &*account };
        if account.pw_uid == 0 || account.pw_gid == 0 {
            return Err(String::from("the pressure job principal must be non-root"));
        }
        Ok((account.pw_uid, account.pw_gid))
    }

    fn require_root() -> Result<(), String> {
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(String::from(
                "the administrative recovery controller requires root",
            ))
        }
    }

    fn ensure_runner_stopped() -> Result<(), String> {
        let enabled = Command::new("/usr/bin/systemctl")
            .args(["is-enabled", RUNNER_SERVICE])
            .output()
            .map_err(|_| String::from("the prepared runner enablement is unavailable"))?;
        if String::from_utf8_lossy(enabled.stdout.as_slice()).trim() != "disabled" {
            return Err(String::from(
                "the prepared repository runner must be disabled during administrative pressure",
            ));
        }
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                RUNNER_SERVICE,
                "--property=ActiveState,SubState,MainPID",
                "--value",
            ])
            .output()
            .map_err(|_| String::from("the prepared runner state is unavailable"))?;
        let state = String::from_utf8_lossy(output.stdout.as_slice());
        if !output.status.success()
            || !state.lines().any(|line| line == "inactive")
            || !state.lines().any(|line| line == "dead")
            || !state.lines().any(|line| line == "0")
        {
            return Err(String::from(
                "the prepared repository runner must be inactive before administrative pressure",
            ));
        }
        Ok(())
    }

    fn require_no_principal_processes(uids: &[u32]) -> Result<(), String> {
        let mut live = Vec::new();
        let processes = fs::read_dir("/proc")
            .map_err(|_| String::from("principal process inventory is unavailable"))?;
        for process in processes {
            let process = process
                .map_err(|_| String::from("principal process inventory entry is unavailable"))?;
            let name = process.file_name();
            let Some(pid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
                continue;
            };
            let status = match fs::read_to_string(process.path().join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(String::from("principal process posture is unavailable")),
            };
            let uid = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| String::from("principal process identity is malformed"))?;
            if uids.contains(&uid) {
                live.push(pid);
            }
        }
        if live.is_empty() {
            Ok(())
        } else {
            live.sort_unstable();
            Err(format!(
                "administrator recovery requires an empty principal process inventory: {live:?}"
            ))
        }
    }

    fn installation_evidence_reference() -> Result<InstallationEvidenceReference, String> {
        let value: serde_json::Value = read_protected_json(Path::new(
            "/usr/share/ota/authority-launcher/installation-evidence.json",
        ))?;
        let observed_identity = semantic_identity(INSTALLATION_EVIDENCE_IDENTITY_DOMAIN, &value)?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or_else(|| format!("installation evidence field is unavailable: {name}"))
        };
        let identity = value
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .filter(|identity| identity.starts_with("sha256:"))
            .map(String::from)
            .ok_or_else(|| String::from("installation evidence identity is unavailable"))?;
        if identity != observed_identity {
            return Err(String::from("installation evidence identity is invalid"));
        }
        let precondition = value
            .get("prepared_provisioning_observation")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| String::from("prepared provisioning observation is unavailable"))?;
        let precondition_value = serde_json::Value::Object(precondition.clone());
        let precondition_identity = precondition
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| String::from("prepared provisioning identity is unavailable"))?;
        if semantic_identity(
            PROVISIONING_OBSERVATION_IDENTITY_DOMAIN,
            &precondition_value,
        )? != precondition_identity
            || precondition
                .get("runner_service_unit")
                .and_then(serde_json::Value::as_str)
                != Some(RUNNER_SERVICE)
            || precondition
                .get("runner_active_state")
                .and_then(serde_json::Value::as_str)
                != Some("inactive")
            || precondition
                .get("runner_sub_state")
                .and_then(serde_json::Value::as_str)
                != Some("dead")
            || precondition
                .get("runner_main_pid")
                .and_then(serde_json::Value::as_u64)
                != Some(0)
            || precondition
                .get("live_principal_processes")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|processes| !processes.is_empty())
            || precondition
                .get("authority_state_posture")
                .and_then(serde_json::Value::as_str)
                != Some("fresh_managed_authority_state")
            || precondition
                .get("authority_state_ancestor_posture")
                .and_then(serde_json::Value::as_str)
                != Some("root_owned_non_writable_directory_chain_without_aliases")
            || precondition
                .get("authority_unit_posture")
                .and_then(serde_json::Value::as_str)
                != Some("inactive_or_not_found_before_mutation")
            || precondition
                .get("authority_socket_listener_posture")
                .and_then(serde_json::Value::as_str)
                != Some("no_loaded_systemd_socket_unit_owns_managed_path_before_mutation")
        {
            return Err(String::from("prepared provisioning observation is invalid"));
        }
        let expected_authority_units = [
            "ota-authority-launcher.service",
            "ota-authority-launcher.socket",
            "ota-authority-attestor.service",
            "ota-authority-attestor.socket",
            "ota-authority-broker-proxy.service",
            "ota-authority-broker-proxy.socket",
            "ota-authority-history.service",
            "ota-authority-history.socket",
        ];
        let observed_authority_units = precondition
            .get("authority_units_checked")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| String::from("prepared authority unit inventory is unavailable"))?;
        if observed_authority_units.len() != expected_authority_units.len()
            || observed_authority_units
                .iter()
                .zip(expected_authority_units)
                .any(|(observed, expected)| observed.as_str() != Some(expected))
        {
            return Err(String::from("prepared authority unit inventory is invalid"));
        }
        let expected_authority_socket_paths = [
            "/run/ota/authority-launcher.sock",
            "/run/ota/authority-attestor.sock",
            "/run/ota/broker-proxy.sock",
            "/run/ota/authority-history.sock",
        ];
        let observed_authority_socket_paths = precondition
            .get("authority_socket_paths_checked")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| String::from("prepared authority socket inventory is unavailable"))?;
        if observed_authority_socket_paths.len() != expected_authority_socket_paths.len()
            || observed_authority_socket_paths
                .iter()
                .zip(expected_authority_socket_paths)
                .any(|(observed, expected)| observed.as_str() != Some(expected))
        {
            return Err(String::from(
                "prepared authority socket inventory is invalid",
            ));
        }
        let job_uid = precondition
            .get("job_uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| String::from("prepared job principal is invalid"))?;
        let execution_uid = precondition
            .get("execution_uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0 && *value != job_uid)
            .ok_or_else(|| String::from("prepared execution principal is invalid"))?;
        let reference = InstallationEvidenceReference {
            identity,
            protocol_source_revision: field("protocol_source_revision")?,
            core_source_revision: field("core_source_revision")?,
            launcher_source_revision: field("launcher_source_revision")?,
            job_uid,
            execution_uid,
        };
        for revision in [
            reference.protocol_source_revision.as_str(),
            reference.core_source_revision.as_str(),
            reference.launcher_source_revision.as_str(),
        ] {
            if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(String::from("installation source revision is invalid"));
            }
        }
        let embedded_protocol = option_env!("OTA_PROTOCOL_BUILD_REVISION")
            .ok_or_else(|| String::from("controller Protocol build revision is unavailable"))?;
        let embedded_launcher = option_env!("OTA_LAUNCHER_BUILD_COMMIT")
            .ok_or_else(|| String::from("controller Launcher build revision is unavailable"))?;
        if option_env!("OTA_LAUNCHER_BUILD_DIRTY").is_some()
            || embedded_protocol != reference.protocol_source_revision
            || embedded_launcher != reference.launcher_source_revision
        {
            return Err(String::from(
                "controller source identity does not match installation evidence",
            ));
        }
        Ok(reference)
    }

    fn load_state() -> Result<RecoveryStateV1, String> {
        let state: RecoveryStateV1 = read_protected_json(Path::new(STATE_PATH))?;
        if semantic_identity(STATE_IDENTITY_DOMAIN, &state)? != state.identity {
            return Err(String::from("pending recovery state identity is invalid"));
        }
        Ok(state)
    }

    fn observe_fault(mut state: RecoveryStateV1) -> Result<RecoveryStateV1, String> {
        require_absent(
            Path::new(state.fault.marker_path()),
            "consumed fault marker",
        )?;
        let checkpoint = inspect_retained_checkpoint(state.fault)?;
        let retained_active_records = u64::from(checkpoint.kind == "active_slot");
        let retained_finalization_records = u64::from(checkpoint.kind == "finalization");
        let previous_identity = state.identity.clone();
        state.previous_identity = Some(previous_identity.clone());
        state.prepared_state_identity = previous_identity;
        state.stage = ControllerStage::FaultObserved;
        state.retained_active_records = retained_active_records;
        state.retained_finalization_records = retained_finalization_records;
        state.retained_record_kind = checkpoint.kind;
        state.retained_record_stage = checkpoint.stage;
        state.retained_record_identity = checkpoint.identity;
        state.invocation_id = checkpoint.invocation_id;
        state.receipt_archive_identity = checkpoint.receipt_archive_identity;
        state.crossing_transaction_identity = checkpoint.crossing_transaction_identity;
        state.identity = semantic_identity(STATE_IDENTITY_DOMAIN, &state)?;
        replace_protected_json(Path::new(STATE_PATH), &state, 0o600)?;
        Ok(state)
    }

    fn inspect_retained_checkpoint(fault: FaultPoint) -> Result<RetainedCheckpoint, String> {
        let (kind, directory, expected_stage, completion_path): (&str, &Path, &str, &[&str]) =
            match fault {
                FaultPoint::ExecutionCompletion => (
                    "active_slot",
                    Path::new("/var/lib/ota/authority-launcher/active"),
                    "execution_completion_recorded",
                    &["execution_completion"],
                ),
                FaultPoint::FinalizationIntent => (
                    "finalization",
                    Path::new("/var/lib/ota/authority-launcher/finalization"),
                    "intent",
                    &["finalization", "completion"],
                ),
                FaultPoint::TerminalRecorded => (
                    "finalization",
                    Path::new("/var/lib/ota/authority-launcher/finalization"),
                    "terminal_issued",
                    &["finalization", "completion"],
                ),
            };
        let opposite = if kind == "active_slot" {
            Path::new("/var/lib/ota/authority-launcher/finalization")
        } else {
            Path::new("/var/lib/ota/authority-launcher/active")
        };
        if regular_file_count(opposite)? != 0 {
            return Err(String::from(
                "the fault retained an unexpected journal family",
            ));
        }
        let value = single_protected_record(directory)?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or_else(|| format!("retained recovery record omits {name}"))
        };
        let stage = field("stage")?;
        if stage != expected_stage {
            return Err(String::from(
                "the retained recovery checkpoint is incorrect",
            ));
        }
        let mut completion = &value;
        for component in completion_path {
            completion = completion
                .get(*component)
                .ok_or_else(|| String::from("retained completion evidence is unavailable"))?;
        }
        let completion_field = |name: &str| {
            completion
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or_else(|| format!("retained completion omits {name}"))
        };
        let claimed_identity = field("identity")?;
        let identity_domain = if kind == "active_slot" {
            ACTIVE_SLOT_IDENTITY_DOMAIN
        } else {
            FINALIZATION_JOURNAL_IDENTITY_DOMAIN
        };
        if semantic_identity(identity_domain, &value)? != claimed_identity {
            return Err(String::from(
                "the retained recovery record identity is invalid",
            ));
        }
        Ok(RetainedCheckpoint {
            kind: kind.into(),
            stage,
            identity: claimed_identity,
            invocation_id: field("invocation_id")?,
            receipt_archive_identity: completion_field("receipt_archive_identity")?,
            crossing_transaction_identity: completion_field("crossing_transaction_identity")?,
        })
    }

    fn single_protected_record(directory: &Path) -> Result<serde_json::Value, String> {
        verify_root_directory_chain(directory)?;
        let mut entries = fs::read_dir(directory)
            .map_err(|_| String::from("retained recovery directory is unavailable"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| String::from("retained recovery inventory failed"))?;
        if entries.len() != 1 {
            return Err(String::from(
                "the fault did not retain exactly one protected recovery record",
            ));
        }
        let path = entries.remove(0).path();
        let metadata = fs::symlink_metadata(path.as_path())
            .map_err(|_| String::from("retained recovery metadata is unavailable"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(String::from("retained recovery metadata is invalid"));
        }
        let bytes =
            fs::read(path).map_err(|_| String::from("retained recovery record is unavailable"))?;
        serde_json::from_slice(bytes.as_slice())
            .map_err(|_| String::from("retained recovery record is malformed"))
    }

    fn read_protected_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| String::from("protected controller state is unavailable"))?;
        verify_root_directory_chain(
            path.parent()
                .ok_or_else(|| String::from("protected controller state has no parent"))?,
        )?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(String::from(
                "protected controller state metadata is invalid",
            ));
        }
        let bytes = fs::read(path)
            .map_err(|_| String::from("protected controller state could not be read"))?;
        serde_json::from_slice(bytes.as_slice())
            .map_err(|_| String::from("protected controller state is malformed"))
    }

    fn write_protected_json<T: Serialize>(
        path: &Path,
        value: &T,
        mode: u32,
        create_evidence_root: bool,
    ) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| String::from("protected output has no parent"))?;
        let expected_root = if create_evidence_root {
            Path::new(EVIDENCE_ROOT)
        } else {
            Path::new(STATE_ROOT)
        };
        if parent != expected_root {
            return Err(String::from("protected output path is not canonical"));
        }
        ensure_protected_output_directory(parent)?;
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|_| String::from("failed to encode protected output"))?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name().unwrap().to_string_lossy(),
            unsafe { libc::getpid() }
        ));
        require_absent(temporary.as_path(), "temporary protected output")?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temporary.as_path())
            .map_err(|_| String::from("failed to create protected output"))?;
        output
            .write_all(bytes.as_slice())
            .and_then(|()| output.sync_all())
            .map_err(|_| String::from("failed to persist protected output"))?;
        drop(output);
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                CString::new(temporary.as_os_str().as_encoded_bytes())
                    .unwrap()
                    .as_ptr(),
                libc::AT_FDCWD,
                CString::new(path.as_os_str().as_encoded_bytes())
                    .unwrap()
                    .as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            let _ = fs::remove_file(temporary);
            return Err(String::from(
                "protected output already exists or could not be published",
            ));
        }
        fsync_directory(parent)
    }

    fn replace_protected_json<T: Serialize>(
        path: &Path,
        value: &T,
        mode: u32,
    ) -> Result<(), String> {
        let _: serde_json::Value = read_protected_json(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| String::from("protected output has no parent"))?;
        if parent != Path::new(STATE_ROOT) {
            return Err(String::from("protected replacement path is not canonical"));
        }
        let temporary = parent.join(format!(
            ".{}.replace-{}",
            path.file_name().unwrap().to_string_lossy(),
            unsafe { libc::getpid() }
        ));
        require_absent(temporary.as_path(), "temporary protected replacement")?;
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|_| String::from("failed to encode protected replacement"))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temporary.as_path())
            .map_err(|_| String::from("failed to create protected replacement"))?;
        output
            .write_all(bytes.as_slice())
            .and_then(|()| output.sync_all())
            .map_err(|_| String::from("failed to persist protected replacement"))?;
        drop(output);
        fs::rename(temporary.as_path(), path)
            .map_err(|_| String::from("failed to publish protected replacement"))?;
        fsync_directory(parent)
    }

    fn create_root_marker(path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| String::from("fault marker has no parent"))?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| String::from("fault-marker parent is unavailable"))?;
        verify_root_directory_chain(parent)?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(String::from("fault-marker parent is not root protected"));
        }
        let marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| String::from("failed to create the one-shot fault marker"))?;
        marker
            .sync_all()
            .map_err(|_| String::from("failed to persist the one-shot fault marker"))?;
        fsync_directory(parent)
    }

    fn remove_unconsumed_marker_if_present(path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| String::from("fault marker has no parent"))?;
        verify_root_directory_chain(parent)?;
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(String::from("the unconsumed fault marker is unavailable")),
        };
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.len() != 0
        {
            return Err(String::from("the unconsumed fault marker is invalid"));
        }
        fs::remove_file(path)
            .map_err(|_| String::from("failed to remove the unconsumed fault marker"))?;
        fsync_directory(parent)
    }

    fn require_absent(path: &Path, label: &str) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(format!("{label} already exists")),
            Err(_) => Err(format!("{label} could not be inspected")),
        }
    }

    fn regular_file_count(path: &Path) -> Result<u64, String> {
        match fs::read_dir(path) {
            Ok(entries) => {
                let mut count = 0_u64;
                for entry in entries {
                    let entry =
                        entry.map_err(|_| String::from("recovery state inventory failed"))?;
                    let metadata = fs::symlink_metadata(entry.path())
                        .map_err(|_| String::from("recovery state metadata is unavailable"))?;
                    if !metadata.file_type().is_file() {
                        return Err(String::from(
                            "recovery state inventory contains a non-regular entry",
                        ));
                    }
                    count += 1;
                }
                Ok(count)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(_) => Err(String::from("recovery state directory is unavailable")),
        }
    }

    fn execution_count(repository: &Path) -> Result<u64, String> {
        let value = match fs::read_to_string(repository.join("selected-work-executed")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => return Err(String::from("selected-execution sentinel is unavailable")),
        };
        Ok(value.lines().filter(|line| *line == "executed").count() as u64)
    }

    fn repository_manifest(repository: &Path) -> Result<String, String> {
        fn visit(
            root: &Path,
            current: &Path,
            entries: &mut Vec<(String, Vec<u8>)>,
        ) -> Result<(), String> {
            let mut children = fs::read_dir(current)
                .map_err(|_| String::from("repository manifest could not be read"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| String::from("repository manifest entry is unavailable"))?;
            children.sort_by_key(|entry| entry.file_name());
            for entry in children {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| String::from("repository manifest path escaped"))?;
                if relative == Path::new(".ota")
                    || relative == Path::new("selected-work-executed")
                    || relative.starts_with(".ota/")
                {
                    continue;
                }
                let metadata = fs::symlink_metadata(path.as_path())
                    .map_err(|_| String::from("repository manifest metadata is unavailable"))?;
                if metadata.file_type().is_symlink() {
                    return Err(String::from("repository manifest contains a symlink"));
                }
                if metadata.is_dir() {
                    visit(root, path.as_path(), entries)?;
                } else if metadata.is_file() {
                    entries.push((
                        relative.to_string_lossy().into_owned(),
                        fs::read(path)
                            .map_err(|_| String::from("repository file is unavailable"))?,
                    ));
                }
            }
            Ok(())
        }
        let mut entries = Vec::new();
        visit(repository, repository, &mut entries)?;
        let mut hash = Sha256::new();
        hash.update(b"ota.authority-launcher.admin-recovery-repository-manifest.v1\0");
        for (path, bytes) in entries {
            hash.update((path.len() as u64).to_be_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(format!("sha256:{:x}", hash.finalize()))
    }

    fn residual_scope_units() -> Result<Vec<String>, String> {
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "list-units",
                "--type=scope",
                "--all",
                "--plain",
                "--no-legend",
            ])
            .output()
            .map_err(|_| String::from("scope inventory is unavailable"))?;
        if !output.status.success() {
            return Err(String::from("scope inventory failed"));
        }
        Ok(String::from_utf8_lossy(output.stdout.as_slice())
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|unit| unit.starts_with("ota-authority-"))
            .map(String::from)
            .collect())
    }

    fn boot_id() -> Result<String, String> {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|value| value.trim().to_owned())
            .map_err(|_| String::from("kernel boot identity is unavailable"))
    }

    fn ensure_protected_output_directory(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(_) => verify_root_directory_chain(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .ok_or_else(|| String::from("protected output root has no parent"))?;
                verify_root_directory_chain(parent)?;
                fs::create_dir(path)
                    .map_err(|_| String::from("failed to create protected output directory"))?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                    .map_err(|_| String::from("failed to protect output directory"))?;
                fsync_directory(parent)?;
                verify_root_directory_chain(path)
            }
            Err(_) => Err(String::from("protected output directory is unavailable")),
        }
    }

    fn verify_root_directory_chain(path: &Path) -> Result<(), String> {
        let mut current = path.to_path_buf();
        loop {
            let metadata = fs::symlink_metadata(current.as_path())
                .map_err(|_| String::from("protected directory chain is unavailable"))?;
            if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
            {
                return Err(String::from("protected directory chain is unsafe"));
            }
            if current == Path::new("/") {
                break;
            }
            let parent = current
                .parent()
                .ok_or_else(|| String::from("protected directory chain is invalid"))?;
            current = parent.to_path_buf();
        }
        Ok(())
    }

    fn file_identity(path: &Path) -> Result<String, String> {
        verify_root_directory_chain(
            path.parent()
                .ok_or_else(|| String::from("protected executable has no parent"))?,
        )?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| String::from("protected executable is unavailable"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(String::from("protected executable metadata is invalid"));
        }
        let bytes =
            fs::read(path).map_err(|_| String::from("protected executable could not be read"))?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn now() -> Result<String, String> {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| String::from("controller time is unavailable"))
    }

    fn semantic_identity<T: Serialize>(domain: &[u8], value: &T) -> Result<String, String> {
        let mut canonical = serde_json::to_value(value)
            .map_err(|_| String::from("semantic identity input is invalid"))?;
        if let Some(object) = canonical.as_object_mut() {
            object.insert("identity".into(), serde_json::Value::String(String::new()));
        }
        let bytes = serde_jcs::to_vec(&canonical)
            .map_err(|_| String::from("semantic identity input is not canonical"))?;
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(bytes);
        Ok(format!("sha256:{:x}", hash.finalize()))
    }

    fn fsync_directory(path: &Path) -> Result<(), String> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| String::from("failed to synchronize protected output directory"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fault_points_map_only_to_fixed_one_shot_markers() {
            assert_eq!(
                FaultPoint::ExecutionCompletion.marker_path(),
                "/run/ota/authority-launcher-pressure-exit-after-execution-completion"
            );
            assert_eq!(
                FaultPoint::FinalizationIntent.marker_path(),
                "/run/ota/authority-launcher-pressure-exit-after-finalization-intent"
            );
            assert_eq!(
                FaultPoint::TerminalRecorded.marker_path(),
                "/run/ota/authority-launcher-pressure-exit-after-terminal-recorded"
            );
        }

        #[test]
        fn repository_manifest_excludes_only_runtime_evidence() {
            let directory = tempfile::tempdir().expect("tempdir");
            fs::write(directory.path().join("ota.yaml"), b"version: 1\n").expect("contract");
            let initial = repository_manifest(directory.path()).expect("initial manifest");
            fs::write(
                directory.path().join("selected-work-executed"),
                b"executed\n",
            )
            .expect("sentinel");
            fs::create_dir(directory.path().join(".ota")).expect("runtime directory");
            fs::write(directory.path().join(".ota/receipt.json"), b"runtime").expect("runtime");
            assert_eq!(
                repository_manifest(directory.path()).expect("runtime manifest"),
                initial
            );
            fs::write(directory.path().join("ota.yaml"), b"version: 2\n").expect("mutation");
            assert_ne!(
                repository_manifest(directory.path()).expect("mutated manifest"),
                initial
            );
        }

        #[test]
        fn missing_execution_sentinel_is_zero_executions() {
            let directory = tempfile::tempdir().expect("tempdir");
            assert_eq!(execution_count(directory.path()).expect("count"), 0);
        }

        #[test]
        fn retained_record_identity_domains_are_distinct() {
            let value = serde_json::json!({
                "schema_version": 1,
                "identity": "",
                "stage": "execution_completion_recorded",
            });
            assert_ne!(
                semantic_identity(ACTIVE_SLOT_IDENTITY_DOMAIN, &value).expect("active identity"),
                semantic_identity(FINALIZATION_JOURNAL_IDENTITY_DOMAIN, &value)
                    .expect("finalization identity")
            );
        }

        #[test]
        fn root_control_reaches_the_exact_constrained_principal_posture() {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid == 0 {
                let exact = enter_exact_principal(65_534, 65_534);
                unsafe { libc::_exit(u8::from(!exact).into()) }
            }
            let mut status = 0_i32;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }

        #[test]
        fn root_command_spawn_clears_groups_before_dropping_privilege() {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let mut command = Command::new("/usr/bin/id");
            command.arg("-u").env_clear();
            configure_exact_principal(&mut command, 65_534, 65_534);
            let output = command.output().expect("spawn constrained child");
            assert!(output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "65534");
        }

        #[test]
        fn protected_directory_chain_accepts_the_filesystem_root() {
            verify_root_directory_chain(Path::new("/"))
                .expect("the canonical root terminates the protected chain");
        }
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ota-authority-systemd-recovery-controller: Linux is required");
        std::process::ExitCode::from(70)
    }

    #[cfg(target_os = "linux")]
    match linux::main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ota-authority-systemd-recovery-controller: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
