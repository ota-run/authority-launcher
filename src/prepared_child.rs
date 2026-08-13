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

//! Stopped fixed-binary child preparation for the systemd launcher.
//!
//! The child remains root and stopped until the launcher has durably recorded its identity and
//! bound it to the exact systemd invocation scope. The resume path admits one bounded Ota
//! process-posture preface, one signed V3 attestation bridge, and one bounded authorization-decision
//! relay, then retains the exact child for selected execution after one consumed lease.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ota_authority_protocol::{
    ATTESTATION_RESPONSE, AUTHORIZATION_DECISION, AUTHORIZATION_DECISION_DOMAIN_V1,
    AUTHORIZATION_REQUEST, AUTHORIZATION_REQUEST_DOMAIN_V1, AuthorizationDecision,
    AuthorizationDecisionAdmissionV1, AuthorizationDecisionPayload,
    AuthorizationDecisionRelayEvidenceV1, AuthorizationRequest, BrokerChallenge,
    LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE, LAUNCHER_OUTPUT, LEASE_CONSUME,
    LEASE_CONSUME_RESPONSE, LEASE_CONSUMPTION_INTENT_PERSISTENCE, LEASE_CONSUMPTION_PERSISTENCE,
    LEASE_ISSUANCE, LauncherChildProcessV1, LauncherExecutionCompletionPersistenceV1,
    LauncherExecutionCompletionV1, LauncherOutputFrameV1, LauncherOutputStreamV1,
    LauncherStartupContinuationV1, LeaseConsumeRequest, LeaseConsumeResponsePayload,
    LeaseConsumptionAdmissionV1, LeaseConsumptionIntentPersistenceV1,
    LeaseConsumptionIntentRelayEvidenceV1, LeaseConsumptionPersistenceV1,
    LeaseConsumptionRelayEvidenceV1, MAX_FRAME_BYTES, OtaProcessPostureV1, PreparedLeasePayload,
    SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3,
    SignedBrokerMessage, SignedLauncherAttestationV3, authorization_decision_admission_v1_identity,
    authorization_decision_relay_evidence_v1_identity, decode_frame, encode_frame,
    launcher_attestation_identity_v3, launcher_child_process_identity,
    launcher_execution_completion_persistence_v1_identity,
    launcher_execution_completion_v1_identity, launcher_startup_continuation_identity,
    lease_consumption_admission_v1_identity, lease_consumption_intent_persistence_v1_identity,
    lease_consumption_intent_relay_evidence_v1_identity, lease_consumption_persistence_v1_identity,
    lease_consumption_relay_evidence_v1_identity, message_identity, ota_process_posture_identity,
    sha256_identity, validate_launcher_output_frame_v1,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::config::{RunAs, SystemdLauncherServiceConfigV1};
use crate::target_directory::OpenedRepositoryDirectory;

pub(crate) const SYSTEMD_OTA_SESSION_DESCRIPTOR: RawFd = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PreparedChildError {
    #[error("the protected Ota child inputs are invalid")]
    InvalidInputs,
    #[error("the protected Ota child could not be created")]
    ForkFailed,
    #[error("the protected Ota child did not stop before execution")]
    StopFailed,
    #[error("the protected Ota child exited and was reaped before it stopped")]
    ExitedBeforeStop,
    #[error("the protected Ota child identity could not be observed")]
    IdentityUnavailable,
    #[error("the protected Ota child could not be terminated")]
    CleanupFailed,
    #[error("the protected Ota child could not be resumed")]
    ResumeFailed,
    #[error("the protected Ota child process posture is unavailable")]
    PostureUnavailable,
    #[error("the protected Ota child process posture does not match the prepared child")]
    PostureMismatch,
    #[error("the protected Ota child attestation bridge is unavailable")]
    AttestationBridgeUnavailable,
    #[error("the protected Ota child did not reach exact authorization admission")]
    AuthorizationAdmissionMismatch,
    #[error("the protected Ota child authorization decision bridge is unavailable")]
    AuthorizationDecisionBridgeUnavailable,
    #[error("the protected Ota child execution completion is unavailable")]
    ExecutionCompletionUnavailable,
    #[error("the protected Ota child execution completion does not match the consumed lease")]
    ExecutionCompletionIdentityMismatch,
    #[error("the protected Ota child execution completion could not be persisted")]
    ExecutionCompletionPersistenceFailed,
    #[error("the protected Ota child exit does not match its signed execution completion")]
    ExecutionCompletionExitMismatch,
    #[error("the protected Ota child output bridge is unavailable")]
    OutputBridgeUnavailable,
}

pub(crate) struct PreparedChild {
    pid: libc::pid_t,
    pub record: LauncherChildProcessV1,
    launcher_session: UnixStream,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
}

pub(crate) struct PreparedChildBinding<'a> {
    pub invocation_id: &'a str,
    pub request_identity: &'a str,
    pub principal_mapping_identity: &'a str,
    pub working_directory_identity: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DescriptorObject {
    device: u64,
    inode: u64,
    file_type: u32,
}

impl PreparedChild {
    pub(crate) fn resume_and_receive_process_posture(
        &mut self,
        expected_principal_mapping_identity: &str,
        timeout: Duration,
    ) -> Result<OtaProcessPostureV1, PreparedChildError> {
        if self.pid <= 0
            || process_start_identity(self.pid)? != self.record.process_start_time_identity
        {
            return Err(PreparedChildError::IdentityUnavailable);
        }
        let pidfd = pidfd_open(self.pid).map_err(|_| PreparedChildError::ResumeFailed)?;
        if process_start_identity(self.pid)? != self.record.process_start_time_identity
            || unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGCONT,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            } < 0
        {
            return Err(PreparedChildError::ResumeFailed);
        }

        self.receive_process_posture_after_resume(expected_principal_mapping_identity, timeout)
    }

    #[cfg(test)]
    pub(crate) fn continue_and_bridge_v3_attestation(
        &mut self,
        posture: &OtaProcessPostureV1,
        broker_proxy: &mut UnixStream,
        timeout: Duration,
    ) -> Result<(), PreparedChildError> {
        self.continue_with_v3_attestation(posture, timeout, |challenge| {
            write_json_frame(broker_proxy, challenge, timeout)?;
            read_json_frame(broker_proxy, timeout)
        })
    }

    #[cfg(test)]
    pub(crate) fn continue_with_v3_attestation(
        &mut self,
        posture: &OtaProcessPostureV1,
        timeout: Duration,
        produce: impl FnOnce(
            &BrokerChallenge,
        ) -> Result<SignedLauncherAttestationV3, PreparedChildError>,
    ) -> Result<(), PreparedChildError> {
        self.continue_to_v3_authorization_request(posture, timeout, produce)
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relay_v3_authorization_decisions(
        &mut self,
        authorization: &AuthorizationRequest,
        request_identity: &str,
        broker_proxy: &mut UnixStream,
        timeout: Duration,
        mut record: impl FnMut(&AuthorizationDecisionRelayEvidenceV1) -> Result<(), PreparedChildError>,
        mut record_consumption: impl FnMut(
            &LeaseConsumptionRelayEvidenceV1,
        ) -> Result<(), PreparedChildError>,
        mut record_consumption_intent: impl FnMut(
            &LeaseConsumptionIntentRelayEvidenceV1,
        ) -> Result<(), PreparedChildError>,
    ) -> Result<
        (
            AuthorizationDecision,
            Option<LeaseConsumptionRelayEvidenceV1>,
        ),
        PreparedChildError,
    > {
        write_json_frame(broker_proxy, &authorization, timeout)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        pressure_v3_stage("authorization_request_forwarded");

        loop {
            let decision: SignedBrokerMessage<AuthorizationDecisionPayload> =
                read_json_frame(broker_proxy, timeout)
                    .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
            if decision.payload.message_kind != AUTHORIZATION_DECISION {
                return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
            }
            let decision_identity =
                message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), &decision)
                    .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
            write_json_frame(&mut self.launcher_session, &decision, timeout)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
            pressure_v3_stage("authorization_decision_relayed");
            let admission: AuthorizationDecisionAdmissionV1 =
                read_json_frame(&mut self.launcher_session, timeout)
                    .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
            if authorization_decision_admission_v1_identity(&admission)
                .ok()
                .as_deref()
                != Some(admission.identity.as_str())
                || admission.request_identity != request_identity
                || admission.authorization_decision_identity != decision_identity
                || admission.binding_identity != authorization.binding_identity
                || admission.attestation_identity != authorization.attestation_identity
                || admission.work_unit_identity != authorization.work_unit_identity
                || admission.contract_identity != authorization.contract_identity
                || admission.semantic_scope_identity != authorization.semantic_scope_identity
                || admission.decision != decision.payload.decision
            {
                return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
            }
            let mut evidence = AuthorizationDecisionRelayEvidenceV1 {
                schema_version: 1,
                identity: String::new(),
                request_identity: request_identity.to_string(),
                authorization_decision: decision,
                authorization_decision_identity: decision_identity,
                admission,
            };
            evidence.identity = authorization_decision_relay_evidence_v1_identity(&evidence)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
            record(&evidence)?;
            pressure_v3_relay_evidence(&evidence)?;
            pressure_v3_stage("authorization_decision_verified");
            match evidence.authorization_decision.payload.decision {
                AuthorizationDecision::Pending => {}
                AuthorizationDecision::Allowed => {
                    let consumption = self.relay_v3_lease_consumption(
                        &evidence,
                        broker_proxy,
                        timeout,
                        &mut record_consumption,
                        &mut record_consumption_intent,
                    )?;
                    return Ok((AuthorizationDecision::Allowed, Some(consumption)));
                }
                AuthorizationDecision::Denied => {
                    return Ok((evidence.authorization_decision.payload.decision, None));
                }
            }
        }
    }

    fn relay_v3_lease_consumption(
        &mut self,
        decision: &AuthorizationDecisionRelayEvidenceV1,
        broker_proxy: &mut UnixStream,
        timeout: Duration,
        record: &mut impl FnMut(&LeaseConsumptionRelayEvidenceV1) -> Result<(), PreparedChildError>,
        record_intent: &mut impl FnMut(
            &LeaseConsumptionIntentRelayEvidenceV1,
        ) -> Result<(), PreparedChildError>,
    ) -> Result<LeaseConsumptionRelayEvidenceV1, PreparedChildError> {
        let prepared_lease: SignedBrokerMessage<PreparedLeasePayload> =
            read_json_frame(broker_proxy, timeout)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        if prepared_lease.payload.message_kind != LEASE_ISSUANCE {
            return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
        }
        let prepared_lease_identity = message_identity(
            ota_authority_protocol::LEASE_ISSUANCE_DOMAIN_V1.as_bytes(),
            &prepared_lease,
        )
        .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        if prepared_lease.payload.authorization_decision_identity
            != decision.authorization_decision_identity
            || prepared_lease.payload.binding_identity
                != decision.authorization_decision.payload.binding_identity
            || prepared_lease.payload.work_unit_identity
                != decision.authorization_decision.payload.work_unit_identity
        {
            return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
        }
        write_json_frame(&mut self.launcher_session, &prepared_lease, timeout)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        pressure_v3_stage("prepared_lease_relayed");

        let consume_request: LeaseConsumeRequest =
            read_json_frame(&mut self.launcher_session, timeout).map_err(|_| {
                pressure_v3_stage("lease_consume_unavailable");
                PreparedChildError::AuthorizationDecisionBridgeUnavailable
            })?;
        if consume_request.message_kind != LEASE_CONSUME
            || consume_request.lease_identity != prepared_lease_identity
            || consume_request.binding_identity != prepared_lease.payload.binding_identity
            || consume_request.work_unit_identity != prepared_lease.payload.work_unit_identity
        {
            return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
        }
        let consume_request_identity = message_identity(
            ota_authority_protocol::LEASE_CONSUME_DOMAIN_V1.as_bytes(),
            &consume_request,
        )
        .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        let mut intent = LeaseConsumptionIntentRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            authorization_decision_relay_identity: decision.identity.clone(),
            prepared_lease: prepared_lease.clone(),
            prepared_lease_identity: prepared_lease_identity.clone(),
            consume_request: consume_request.clone(),
            consume_request_identity: consume_request_identity.clone(),
        };
        intent.identity = lease_consumption_intent_relay_evidence_v1_identity(&intent)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        record_intent(&intent).inspect_err(|_| {
            pressure_v3_stage("lease_consumption_intent_recording_failed");
        })?;
        let mut intent_persistence = LeaseConsumptionIntentPersistenceV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LEASE_CONSUMPTION_INTENT_PERSISTENCE.into(),
            consumption_intent_identity: intent.identity.clone(),
        };
        intent_persistence.identity =
            lease_consumption_intent_persistence_v1_identity(&intent_persistence)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        write_json_frame(&mut self.launcher_session, &intent_persistence, timeout).map_err(
            |_| {
                pressure_v3_stage("lease_consumption_intent_acknowledgement_failed");
                PreparedChildError::AuthorizationDecisionBridgeUnavailable
            },
        )?;
        pressure_v3_stage("lease_consumption_intent_persisted");
        crate::systemd_service::pressure_exit_after_intent_persistence_acknowledged()
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        write_json_frame(broker_proxy, &consume_request, timeout)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        pressure_v3_stage("lease_consume_forwarded");

        let consume_response: SignedBrokerMessage<LeaseConsumeResponsePayload> =
            read_json_frame(broker_proxy, timeout)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        if consume_response.payload.message_kind != LEASE_CONSUME_RESPONSE
            || consume_response.payload.consume_request_identity != consume_request_identity
            || consume_response.payload.lease_identity != prepared_lease_identity
            || consume_response.payload.binding_identity != consume_request.binding_identity
            || consume_response.payload.work_unit_identity != consume_request.work_unit_identity
        {
            return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
        }
        let consume_response_identity = message_identity(
            ota_authority_protocol::LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
            &consume_response,
        )
        .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        write_json_frame(&mut self.launcher_session, &consume_response, timeout)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        pressure_v3_stage("lease_consumption_response_relayed");

        let admission: LeaseConsumptionAdmissionV1 =
            read_json_frame(&mut self.launcher_session, timeout)
                .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        if lease_consumption_admission_v1_identity(&admission)
            .ok()
            .as_deref()
            != Some(admission.identity.as_str())
            || admission.prepared_lease_identity != prepared_lease_identity
            || admission.consume_request_identity != consume_request_identity
            || admission.consume_response_identity != consume_response_identity
            || admission.binding_identity != consume_request.binding_identity
            || admission.work_unit_identity != consume_request.work_unit_identity
            || admission.crossing_transaction_id != consume_request.crossing_transaction_id
            || admission.crossing_transaction_identity
                != consume_request.crossing_transaction_identity
        {
            return Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable);
        }
        let mut evidence = LeaseConsumptionRelayEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            authorization_decision_relay_identity: decision.identity.clone(),
            prepared_lease,
            prepared_lease_identity,
            consume_request,
            consume_request_identity,
            consume_response,
            consume_response_identity,
            admission,
        };
        evidence.identity = lease_consumption_relay_evidence_v1_identity(&evidence)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        record(&evidence)?;
        pressure_v3_consumption_evidence(&evidence)?;
        let mut persistence = LeaseConsumptionPersistenceV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LEASE_CONSUMPTION_PERSISTENCE.into(),
            consumption_admission_identity: evidence.admission.identity.clone(),
        };
        persistence.identity = lease_consumption_persistence_v1_identity(&persistence)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        write_json_frame(&mut self.launcher_session, &persistence, timeout)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        pressure_v3_stage("lease_consumption_persisted");
        Ok(evidence)
    }

    pub(crate) fn continue_to_v3_authorization_request(
        &mut self,
        posture: &OtaProcessPostureV1,
        timeout: Duration,
        produce: impl FnOnce(
            &BrokerChallenge,
        ) -> Result<SignedLauncherAttestationV3, PreparedChildError>,
    ) -> Result<(AuthorizationRequest, String), PreparedChildError> {
        let mut continuation = LauncherStartupContinuationV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::LAUNCHER_STARTUP_CONTINUATION.into(),
            invocation_id: self.record.invocation_id.clone(),
            child_process_identity: self.record.identity.clone(),
            working_directory_identity: self.record.working_directory_identity.clone(),
            process_posture_identity: posture.identity.clone(),
            principal_mapping_identity: posture.principal_mapping_identity.clone(),
        };
        continuation.identity = launcher_startup_continuation_identity(&continuation)
            .map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
        write_json_frame(&mut self.launcher_session, &continuation, timeout)?;
        pressure_v3_stage("startup_continuation_sent");

        let challenge: BrokerChallenge = read_json_frame(&mut self.launcher_session, timeout)?;
        pressure_v3_stage("challenge_received");
        if challenge.message_kind != ota_authority_protocol::CHALLENGE_REQUEST
            || challenge.protocol_version != ota_authority_protocol::PROTOCOL_VERSION_V1
        {
            return Err(PreparedChildError::AttestationBridgeUnavailable);
        }
        pressure_v3_stage("challenge_validated");
        let attestation = produce(&challenge)?;
        pressure_v3_stage("attestation_produced");
        let attestation_identity = launcher_attestation_identity_v3(&attestation)
            .map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
        if attestation.payload.message_kind != ATTESTATION_RESPONSE
            || attestation.payload.attestation_protocol_version
                != SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3
            || attestation.payload.binding_identity != challenge.binding_identity
            || attestation.payload.challenge_nonce_commitment != challenge.nonce_commitment
            || attestation.payload.work_unit_identity != challenge.work_unit_identity
            || attestation.payload.semantic_scope_identity != challenge.semantic_scope_identity
            || attestation.payload.invocation_id != self.record.invocation_id
            || attestation.payload.runner_principal != posture.principal_mapping_identity
            || attestation
                .payload
                .systemd_protected_launcher
                .instance_v1
                .child_process_identity
                != self.record.identity
            || attestation
                .payload
                .systemd_protected_launcher
                .instance_v1
                .working_directory_identity
                != self.record.working_directory_identity
            || attestation
                .payload
                .systemd_protected_launcher
                .instance_v1
                .process_posture
                .identity
                != posture.identity
            || attestation
                .payload
                .systemd_protected_launcher
                .instance_v1
                .principal_mapping
                .identity
                != posture.principal_mapping_identity
        {
            return Err(PreparedChildError::AttestationBridgeUnavailable);
        }
        write_json_frame(&mut self.launcher_session, &attestation, timeout)?;
        pressure_v3_stage("attestation_sent");

        let authorization: AuthorizationRequest =
            read_json_frame(&mut self.launcher_session, timeout)?;
        pressure_v3_stage("authorization_received");
        if authorization.message_kind != AUTHORIZATION_REQUEST
            || authorization.binding_identity != challenge.binding_identity
            || authorization.attestation_identity != attestation_identity
            || authorization.challenge_nonce_commitment != challenge.nonce_commitment
            || authorization.work_unit_identity != challenge.work_unit_identity
            || authorization.contract_identity != challenge.contract_identity
            || authorization.semantic_scope_identity != challenge.semantic_scope_identity
            || authorization.runner_principal != attestation.payload.runner_principal
        {
            return Err(PreparedChildError::AuthorizationAdmissionMismatch);
        }

        let request_identity =
            message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &authorization)
                .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
        Ok((authorization, request_identity))
    }

    fn receive_process_posture_after_resume(
        &mut self,
        expected_principal_mapping_identity: &str,
        timeout: Duration,
    ) -> Result<OtaProcessPostureV1, PreparedChildError> {
        let posture = receive_process_posture(&mut self.launcher_session, timeout)?;
        validate_process_posture(&posture, &self.record, expected_principal_mapping_identity)?;
        if process_start_identity(self.pid)? != self.record.process_start_time_identity {
            return Err(PreparedChildError::PostureMismatch);
        }
        Ok(posture)
    }

    pub(crate) fn terminate_and_reap(&mut self) -> Result<(), PreparedChildError> {
        if self.pid <= 0 {
            return Ok(());
        }
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(PreparedChildError::CleanupFailed);
            }
        }
        let mut status = 0;
        loop {
            let observed = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if observed == self.pid {
                self.pid = 0;
                return Ok(());
            }
            if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PreparedChildError::CleanupFailed);
        }
    }

    pub(crate) fn relay_selected_execution(
        &mut self,
        client: &UnixStream,
        consumption: &LeaseConsumptionRelayEvidenceV1,
        mut persist_completion: impl FnMut(
            LauncherExecutionCompletionV1,
        ) -> Result<(), PreparedChildError>,
    ) -> Result<(LauncherExecutionCompletionV1, Option<i32>), PreparedChildError> {
        let stdout = self
            .stdout
            .take()
            .ok_or(PreparedChildError::OutputBridgeUnavailable)?;
        let stderr = self
            .stderr
            .take()
            .ok_or(PreparedChildError::OutputBridgeUnavailable)?;
        let output = Arc::new(Mutex::new((
            client
                .try_clone()
                .map_err(|_| PreparedChildError::OutputBridgeUnavailable)?,
            0_u64,
        )));
        let stdout_thread = spawn_output_relay(
            stdout,
            LauncherOutputStreamV1::Stdout,
            self.record.invocation_id.clone(),
            Arc::clone(&output),
        );
        let stderr_thread = spawn_output_relay(
            stderr,
            LauncherOutputStreamV1::Stderr,
            self.record.invocation_id.clone(),
            output,
        );

        let completion: LauncherExecutionCompletionV1 =
            read_json_frame_blocking(&mut self.launcher_session)
                .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
        if launcher_execution_completion_v1_identity(&completion)
            .ok()
            .as_deref()
            != Some(completion.identity.as_str())
            || completion.invocation_id != self.record.invocation_id
            || completion.lease_consumption_admission_identity != consumption.admission.identity
            || completion.work_unit_identity != consumption.admission.work_unit_identity
            || completion.crossing_transaction_id != consumption.admission.crossing_transaction_id
            || completion.pending_crossing_transaction_identity
                != consumption.admission.crossing_transaction_identity
        {
            return Err(PreparedChildError::ExecutionCompletionIdentityMismatch);
        }
        persist_completion(completion.clone())?;
        let mut persistence = LauncherExecutionCompletionPersistenceV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE.into(),
            completion_identity: completion.identity.clone(),
        };
        persistence.identity = launcher_execution_completion_persistence_v1_identity(&persistence)
            .map_err(|_| PreparedChildError::ExecutionCompletionIdentityMismatch)?;
        write_json_frame_blocking(&mut self.launcher_session, &persistence)
            .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;

        let observed_exit_code = self.wait_and_reap_selected_child()?;
        if stdout_thread.join().ok() != Some(Ok(())) || stderr_thread.join().ok() != Some(Ok(())) {
            return Err(PreparedChildError::OutputBridgeUnavailable);
        }
        if observed_exit_code != completion.exit_code {
            return Err(PreparedChildError::ExecutionCompletionExitMismatch);
        }
        Ok((completion, observed_exit_code))
    }

    fn wait_and_reap_selected_child(&mut self) -> Result<Option<i32>, PreparedChildError> {
        if self.pid <= 0 {
            return Err(PreparedChildError::CleanupFailed);
        }
        let mut status = 0;
        loop {
            let observed = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if observed == self.pid {
                self.pid = 0;
                return if libc::WIFEXITED(status) {
                    Ok(Some(libc::WEXITSTATUS(status)))
                } else if libc::WIFSIGNALED(status) {
                    Ok(Some(128 + libc::WTERMSIG(status)))
                } else {
                    Err(PreparedChildError::CleanupFailed)
                };
            }
            if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PreparedChildError::CleanupFailed);
        }
    }

    #[cfg(test)]
    pub(crate) fn abandon_for_recovery(mut self) {
        self.pid = 0;
    }
}

fn pressure_v3_stage(stage: &'static str) {
    #[cfg(feature = "systemd-pressure-faults")]
    eprintln!("ota-authority-launcher: bounded pressure v3 stage={stage}");
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = stage;
}

fn pressure_v3_relay_evidence(
    evidence: &AuthorizationDecisionRelayEvidenceV1,
) -> Result<(), PreparedChildError> {
    #[cfg(feature = "systemd-pressure-faults")]
    {
        let encoded = serde_json::to_string(evidence)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        eprintln!(
            "ota-authority-launcher: bounded pressure authorization relay evidence={encoded}"
        );
    }
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = evidence;
    Ok(())
}

fn pressure_v3_consumption_evidence(
    evidence: &LeaseConsumptionRelayEvidenceV1,
) -> Result<(), PreparedChildError> {
    #[cfg(feature = "systemd-pressure-faults")]
    {
        let encoded = serde_json::to_string(evidence)
            .map_err(|_| PreparedChildError::AuthorizationDecisionBridgeUnavailable)?;
        eprintln!("ota-authority-launcher: bounded pressure lease relay evidence={encoded}");
    }
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = evidence;
    Ok(())
}

impl Drop for PreparedChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

pub(crate) fn prepare_stopped_child(
    config: &SystemdLauncherServiceConfigV1,
    ota_binary: &File,
    repository: &OpenedRepositoryDirectory,
    execution: &RunAs,
    binding: &PreparedChildBinding<'_>,
    ota_arguments: &[String],
) -> Result<PreparedChild, PreparedChildError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(PreparedChildError::InvalidInputs);
    }
    let argv = child_arguments(ota_arguments)?;
    let mut argv_pointers: Vec<*const libc::c_char> =
        argv.iter().map(|value| value.as_ptr()).collect();
    argv_pointers.push(std::ptr::null());
    let environment = child_environment(&config.environment, binding)?;
    let mut environment_pointers: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    environment_pointers.push(std::ptr::null());
    let (launcher_session, child_session) =
        UnixStream::pair().map_err(|_| PreparedChildError::ForkFailed)?;
    set_cloexec(launcher_session.as_raw_fd())?;
    set_cloexec(child_session.as_raw_fd())?;
    let null = open_null()?;
    let (stdout, child_stdout) = pipe_cloexec()?;
    let (stderr, child_stderr) = pipe_cloexec()?;
    let ota_binary = duplicate_high(ota_binary.as_raw_fd(), 1_000)?;
    let repository_descriptor = duplicate_high(repository.descriptor.as_raw_fd(), 1_000)?;
    let expected_descriptors = [
        (
            libc::STDIN_FILENO,
            descriptor_object(null.as_raw_fd())?,
            false,
        ),
        (
            libc::STDOUT_FILENO,
            descriptor_object(child_stdout.as_raw_fd())?,
            false,
        ),
        (
            libc::STDERR_FILENO,
            descriptor_object(child_stderr.as_raw_fd())?,
            false,
        ),
        (
            SYSTEMD_OTA_SESSION_DESCRIPTOR,
            descriptor_object(child_session.as_raw_fd())?,
            false,
        ),
        (
            ota_binary.as_raw_fd(),
            descriptor_object(ota_binary.as_raw_fd())?,
            true,
        ),
        (
            repository_descriptor.as_raw_fd(),
            descriptor_object(repository_descriptor.as_raw_fd())?,
            true,
        ),
    ];
    let parent_pid = unsafe { libc::getpid() };
    let open_max = open_maximum();

    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    if child_pid == 0 {
        let status = run_child(
            parent_pid,
            child_session.as_raw_fd(),
            SYSTEMD_OTA_SESSION_DESCRIPTOR,
            ota_binary.as_raw_fd(),
            repository_descriptor.as_raw_fd(),
            null.as_raw_fd(),
            child_stdout.as_raw_fd(),
            child_stderr.as_raw_fd(),
            execution,
            argv_pointers.as_slice(),
            environment_pointers.as_slice(),
            open_max,
        );
        unsafe { libc::_exit(status) };
    }
    drop(child_session);
    drop(child_stdout);
    drop(child_stderr);

    if let Err(error) = wait_for_stop(
        child_pid,
        Duration::from_secs(config.maximum_startup_seconds),
    ) {
        if error == PreparedChildError::ExitedBeforeStop {
            return Err(error);
        }
        return Err(failed_prepare_error(child_pid, error));
    }
    if verify_stopped_child(child_pid, &expected_descriptors).is_err() {
        return Err(failed_prepare_error(
            child_pid,
            PreparedChildError::IdentityUnavailable,
        ));
    }
    let process_start_time_identity = match process_start_identity(child_pid) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(failed_prepare_error(child_pid, error));
        }
    };
    let mut record = LauncherChildProcessV1 {
        schema_version: 1,
        identity: String::new(),
        invocation_id: binding.invocation_id.into(),
        request_identity: binding.request_identity.into(),
        pid: child_pid as u32,
        process_start_time_identity,
        ota_binary_identity: config.ota_binary_identity.clone(),
        principal_mapping_identity: binding.principal_mapping_identity.into(),
        working_directory_identity: binding.working_directory_identity.into(),
    };
    record.identity = match launcher_child_process_identity(&record) {
        Ok(identity) => identity,
        Err(_) => {
            return Err(failed_prepare_error(
                child_pid,
                PreparedChildError::IdentityUnavailable,
            ));
        }
    };
    Ok(PreparedChild {
        pid: child_pid,
        record,
        launcher_session,
        stdout: Some(stdout),
        stderr: Some(stderr),
    })
}

fn child_arguments(arguments: &[String]) -> Result<Vec<CString>, PreparedChildError> {
    std::iter::once("ota")
        .chain(arguments.iter().map(String::as_str))
        .map(|argument| CString::new(argument).map_err(|_| PreparedChildError::InvalidInputs))
        .collect()
}

fn child_environment(
    environment: &BTreeMap<String, String>,
    binding: &PreparedChildBinding<'_>,
) -> Result<Vec<CString>, PreparedChildError> {
    let mut environment = environment.clone();
    environment.insert(
        String::from("OTA_LAUNCHER_PRINCIPAL_MAPPING_IDENTITY"),
        binding.principal_mapping_identity.into(),
    );
    environment.insert(
        String::from("OTA_SYSTEMD_LAUNCHER_STARTUP_GATE"),
        String::from("attestation_v1"),
    );
    environment
        .iter()
        .map(|(name, value)| {
            CString::new(format!("{name}={value}")).map_err(|_| PreparedChildError::InvalidInputs)
        })
        .collect()
}

fn receive_process_posture(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<OtaProcessPostureV1, PreparedChildError> {
    let deadline = Instant::now() + timeout;
    let mut header = [0_u8; 4];
    read_exact_until(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PreparedChildError::PostureUnavailable);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    read_exact_until(stream, &mut frame[4..], deadline)?;
    let payload = decode_frame(&frame).map_err(|_| PreparedChildError::PostureUnavailable)?;
    serde_json::from_slice(payload).map_err(|_| PreparedChildError::PostureUnavailable)
}

fn write_json_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    timeout: Duration,
) -> Result<(), PreparedChildError> {
    let payload =
        serde_json::to_vec(value).map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
    let frame =
        encode_frame(&payload).map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
    stream
        .set_write_timeout(Some(timeout))
        .and_then(|()| stream.write_all(&frame))
        .map_err(|_| PreparedChildError::AttestationBridgeUnavailable)
}

fn read_json_frame<T: DeserializeOwned>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<T, PreparedChildError> {
    let deadline = Instant::now() + timeout;
    let mut header = [0_u8; 4];
    read_exact_until(stream, &mut header, deadline)
        .map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PreparedChildError::AttestationBridgeUnavailable);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    read_exact_until(stream, &mut frame[4..], deadline)
        .map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
    let payload =
        decode_frame(&frame).map_err(|_| PreparedChildError::AttestationBridgeUnavailable)?;
    serde_json::from_slice(payload).map_err(|_| PreparedChildError::AttestationBridgeUnavailable)
}

fn read_json_frame_blocking<T: DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<T, PreparedChildError> {
    stream
        .set_read_timeout(None)
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PreparedChildError::ExecutionCompletionUnavailable);
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    serde_json::from_slice(&payload).map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)
}

fn write_json_frame_blocking<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
) -> Result<(), PreparedChildError> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    let frame =
        encode_frame(&payload).map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    stream
        .set_write_timeout(None)
        .and_then(|()| stream.write_all(&frame))
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)
}

fn spawn_output_relay(
    descriptor: OwnedFd,
    stream: LauncherOutputStreamV1,
    invocation_id: String,
    output: Arc<Mutex<(UnixStream, u64)>>,
) -> thread::JoinHandle<Result<(), PreparedChildError>> {
    thread::spawn(move || {
        let mut source = File::from(descriptor);
        let mut payload = vec![0_u8; ota_authority_protocol::MAX_LAUNCHER_OUTPUT_PAYLOAD_BYTES_V1];
        loop {
            let read = match source.read(&mut payload) {
                Ok(0) => return Ok(()),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(PreparedChildError::OutputBridgeUnavailable),
            };
            let mut output = output
                .lock()
                .map_err(|_| PreparedChildError::OutputBridgeUnavailable)?;
            let frame = LauncherOutputFrameV1 {
                message_kind: LAUNCHER_OUTPUT.into(),
                protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
                invocation_id: invocation_id.clone(),
                sequence: output.1,
                stream,
                payload: payload[..read].to_vec(),
            };
            validate_launcher_output_frame_v1(&frame)
                .map_err(|_| PreparedChildError::OutputBridgeUnavailable)?;
            let encoded = serde_json::to_vec(&frame)
                .map_err(|_| PreparedChildError::OutputBridgeUnavailable)?;
            let encoded =
                encode_frame(&encoded).map_err(|_| PreparedChildError::OutputBridgeUnavailable)?;
            output
                .0
                .write_all(&encoded)
                .map_err(|_| PreparedChildError::OutputBridgeUnavailable)?;
            output.1 = output.1.saturating_add(1);
        }
    })
}

fn read_exact_until(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), PreparedChildError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PreparedChildError::PostureUnavailable)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| PreparedChildError::PostureUnavailable)?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Err(PreparedChildError::PostureUnavailable),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PreparedChildError::PostureUnavailable),
        }
    }
    Ok(())
}

fn validate_process_posture(
    posture: &OtaProcessPostureV1,
    child: &LauncherChildProcessV1,
    expected_principal_mapping_identity: &str,
) -> Result<(), PreparedChildError> {
    let derived_identity =
        ota_process_posture_identity(posture).map_err(|_| PreparedChildError::PostureMismatch)?;
    if posture.identity != derived_identity
        || posture.pid != child.pid
        || posture.process_start_time_identity != child.process_start_time_identity
        || posture.ota_binary_identity != child.ota_binary_identity
        || posture.principal_mapping_identity != expected_principal_mapping_identity
    {
        return Err(PreparedChildError::PostureMismatch);
    }
    Ok(())
}

fn open_null() -> Result<OwnedFd, PreparedChildError> {
    let path = c"/dev/null";
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd), PreparedChildError> {
    let mut descriptors = [0; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn run_child(
    parent_pid: libc::pid_t,
    child_session: RawFd,
    session_target: RawFd,
    ota_binary: RawFd,
    repository: RawFd,
    null: RawFd,
    stdout: RawFd,
    stderr: RawFd,
    execution: &RunAs,
    argv: &[*const libc::c_char],
    environment: &[*const libc::c_char],
    open_max: RawFd,
) -> i32 {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::getppid() } != parent_pid
    {
        return 10;
    }
    if !duplicate_descriptor(child_session, session_target, false)
        || !duplicate_descriptor(null, libc::STDIN_FILENO, false)
        || !duplicate_descriptor(stdout, libc::STDOUT_FILENO, false)
        || !duplicate_descriptor(stderr, libc::STDERR_FILENO, false)
    {
        return 11;
    }
    let retained = [session_target, ota_binary, repository];
    if !close_unretained_descriptors(open_max, retained) {
        return 12;
    }

    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return 13;
    }

    if unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            std::ptr::null::<libc::gid_t>(),
        )
    } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_setresgid,
                execution.gid,
                execution.gid,
                execution.gid,
            )
        } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_setresuid,
                execution.uid,
                execution.uid,
                execution.uid,
            )
        } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::fchdir(repository) } != 0
    {
        return 14;
    }
    unsafe { libc::close(repository) };

    unsafe { libc::fexecve(ota_binary, argv.as_ptr(), environment.as_ptr()) };
    15
}

fn duplicate_descriptor(source: RawFd, target: RawFd, cloexec: bool) -> bool {
    if source == target {
        let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
        let desired = if cloexec {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        return flags >= 0 && unsafe { libc::fcntl(target, libc::F_SETFD, desired) } == 0;
    }
    (unsafe { libc::dup3(source, target, if cloexec { libc::O_CLOEXEC } else { 0 }) }) >= 0
}

fn close_unretained_descriptors(open_max: RawFd, retained: [RawFd; 3]) -> bool {
    for descriptor in 3..open_max {
        if !retained.contains(&descriptor) {
            unsafe { libc::close(descriptor) };
        }
    }
    true
}

fn duplicate_high(descriptor: RawFd, minimum: RawFd) -> Result<OwnedFd, PreparedChildError> {
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn set_cloexec(descriptor: RawFd) -> Result<(), PreparedChildError> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(())
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, ()> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) })
}

fn open_maximum() -> RawFd {
    let observed = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if observed <= 0 {
        65_536
    } else {
        observed.min(i32::MAX as libc::c_long) as RawFd
    }
}

fn wait_for_stop(pid: libc::pid_t, timeout: Duration) -> Result<(), PreparedChildError> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        if observed == pid {
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                return Ok(());
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(PreparedChildError::ExitedBeforeStop);
            }
            return Err(PreparedChildError::StopFailed);
        }
        if observed < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PreparedChildError::StopFailed);
        }
        if Instant::now() >= deadline {
            return Err(PreparedChildError::StopFailed);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub(crate) fn process_start_identity(pid: libc::pid_t) -> Result<String, PreparedChildError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    let closing = stat
        .rfind(')')
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    let start_time = stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    Ok(sha256_identity(
        format!("pid:{pid};start_time:{start_time}").as_bytes(),
    ))
}

fn verify_stopped_child(
    pid: libc::pid_t,
    expected_descriptors: &[(RawFd, DescriptorObject, bool)],
) -> Result<(), PreparedChildError> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    if !status.lines().any(|line| line == "State:\tT (stopped)")
        || !status.lines().any(|line| line == "Uid:\t0\t0\t0\t0")
        || !status.lines().any(|line| line == "Gid:\t0\t0\t0\t0")
    {
        return Err(PreparedChildError::IdentityUnavailable);
    }

    let descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?
        .map(|entry| {
            entry
                .map_err(|_| PreparedChildError::IdentityUnavailable)?
                .file_name()
                .to_string_lossy()
                .parse::<RawFd>()
                .map_err(|_| PreparedChildError::IdentityUnavailable)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = expected_descriptors
        .iter()
        .map(|(descriptor, _, _)| *descriptor)
        .collect();
    if descriptors != expected {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    for (descriptor, expected_object, expected_cloexec) in expected_descriptors {
        let metadata = std::fs::metadata(format!("/proc/{pid}/fd/{descriptor}"))
            .map_err(|_| PreparedChildError::IdentityUnavailable)?;
        let observed = DescriptorObject {
            device: metadata.dev(),
            inode: metadata.ino(),
            file_type: metadata.mode() & libc::S_IFMT,
        };
        if observed != *expected_object
            || descriptor_cloexec(pid, *descriptor)? != *expected_cloexec
        {
            return Err(PreparedChildError::IdentityUnavailable);
        }
    }
    Ok(())
}

fn descriptor_object(descriptor: RawFd) -> Result<DescriptorObject, PreparedChildError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut stat) } != 0 {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    Ok(DescriptorObject {
        device: stat.st_dev,
        inode: stat.st_ino,
        file_type: stat.st_mode & libc::S_IFMT,
    })
}

fn descriptor_cloexec(pid: libc::pid_t, descriptor: RawFd) -> Result<bool, PreparedChildError> {
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{descriptor}"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    Ok(flags & libc::O_CLOEXEC as u32 != 0)
}

pub(crate) fn terminate_recorded_child(
    child: &LauncherChildProcessV1,
    timeout: Duration,
) -> Result<(), PreparedChildError> {
    match process_start_identity(child.pid as libc::pid_t) {
        Ok(identity) if identity == child.process_start_time_identity => {}
        Err(PreparedChildError::IdentityUnavailable)
            if !std::path::Path::new(format!("/proc/{}", child.pid).as_str()).exists() =>
        {
            return Ok(());
        }
        _ => return Err(PreparedChildError::IdentityUnavailable),
    }

    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid as libc::pid_t, 0) };
    if descriptor < 0 {
        return Err(PreparedChildError::CleanupFailed);
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) };
    if process_start_identity(child.pid as libc::pid_t)
        .ok()
        .as_deref()
        != Some(child.process_start_time_identity.as_str())
    {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(PreparedChildError::CleanupFailed);
    }
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if result > 0 && poll.revents & libc::POLLIN != 0 {
            let mut status = 0;
            loop {
                let observed =
                    unsafe { libc::waitpid(child.pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if observed >= 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    break;
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(PreparedChildError::CleanupFailed);
    }
}

pub(crate) fn recorded_child_is_live_exact(
    child: &LauncherChildProcessV1,
) -> Result<bool, PreparedChildError> {
    match process_start_identity(child.pid as libc::pid_t) {
        Ok(identity) if identity == child.process_start_time_identity => Ok(true),
        Err(PreparedChildError::IdentityUnavailable)
            if !std::path::Path::new(format!("/proc/{}", child.pid).as_str()).exists() =>
        {
            Ok(false)
        }
        _ => Err(PreparedChildError::IdentityUnavailable),
    }
}

fn failed_prepare_error(pid: libc::pid_t, error: PreparedChildError) -> PreparedChildError {
    match kill_and_reap(pid) {
        Ok(()) => error,
        Err(()) => PreparedChildError::CleanupFailed,
    }
}

fn kill_and_reap(pid: libc::pid_t) -> Result<(), ()> {
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(());
        }
    }
    let mut status = 0;
    loop {
        let observed = unsafe { libc::waitpid(pid, &mut status, 0) };
        if observed == pid {
            return Ok(());
        }
        if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use ota_authority_protocol::{
        AuthorizationRequest, LauncherAttestationPayloadV3, LauncherPrincipalMappingV1,
        LauncherWorkingDirectoryV1, LeaseConsumeState, OTA_PROCESS_POSTURE,
        RuntimeBoundaryObservationState, SignedLauncherAttestationV3,
        SystemdJobPrincipalObservation, SystemdLauncherObservation,
        SystemdProtectedLauncherInstanceEvidenceV1, SystemdProtectedLauncherInstanceEvidenceV2,
        UnixPrincipalIdentity, encode_frame, launcher_principal_mapping_identity,
        launcher_working_directory_identity, systemd_job_principal_profile_identity,
        systemd_job_principal_profile_v2, systemd_launcher_profile_identity,
        systemd_launcher_profile_v3, systemd_protected_launcher_instance_v2_identity,
        systemd_protected_launcher_instance_v3_foundation_identity,
    };
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn process_posture(child: &LauncherChildProcessV1, mapping: &str) -> OtaProcessPostureV1 {
        let mut posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: String::from(OTA_PROCESS_POSTURE),
            pid: child.pid,
            process_start_time_identity: child.process_start_time_identity.clone(),
            ota_binary_identity: child.ota_binary_identity.clone(),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: mapping.into(),
        };
        posture.identity = ota_process_posture_identity(&posture).expect("posture identity");
        posture
    }

    fn attestation_for(
        challenge: &BrokerChallenge,
        child: &LauncherChildProcessV1,
        posture: &OtaProcessPostureV1,
    ) -> SignedLauncherAttestationV3 {
        let principal = |uid, gid| UnixPrincipalIdentity {
            real_uid: uid,
            effective_uid: uid,
            saved_uid: uid,
            filesystem_uid: uid,
            real_gid: gid,
            effective_gid: gid,
            saved_gid: gid,
            filesystem_gid: gid,
        };
        let launcher_profile = systemd_launcher_profile_v3();
        let job_profile = systemd_job_principal_profile_v2();
        let launcher_profile_identity = systemd_launcher_profile_identity(&launcher_profile)
            .expect("launcher profile identity");
        let job_profile_identity =
            systemd_job_principal_profile_identity(&job_profile).expect("job profile identity");
        let mut mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer: principal(1001, 1001),
            execution: principal(1002, 1002),
            job_principal_profile_identity: job_profile_identity.clone(),
            launcher_session_binding_identity: identity('9'),
        };
        mapping.identity = launcher_principal_mapping_identity(&mapping).expect("mapping identity");
        assert_eq!(mapping.identity, posture.principal_mapping_identity);
        let mut instance_v1 = SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: mapping,
            process_posture: posture.clone(),
            systemd_launcher_profile_identity: launcher_profile_identity,
            systemd_job_principal_profile_identity: job_profile_identity,
            launcher_session_binding_identity: identity('9'),
            systemd_invocation_identity: identity('8'),
            working_directory_identity: child.working_directory_identity.clone(),
            child_process_identity: child.identity.clone(),
        };
        instance_v1.identity =
            systemd_protected_launcher_instance_v3_foundation_identity(&instance_v1)
                .expect("instance identity");
        let mut instance = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 3,
            identity: String::new(),
            instance_v1,
            launcher_observations: launcher_profile
                .evidence_sources
                .iter()
                .map(|source| SystemdLauncherObservation {
                    source: *source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_test_launcher"),
                    evidence_identity: Some(identity('7')),
                })
                .collect(),
            job_principal_observations: job_profile
                .requirements
                .iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods.clone(),
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: String::from("verified_by_test_launcher"),
                    evidence_identity: Some(identity('8')),
                })
                .collect(),
        };
        instance.identity = systemd_protected_launcher_instance_v2_identity(&instance)
            .expect("complete instance identity");
        SignedLauncherAttestationV3 {
            payload: LauncherAttestationPayloadV3 {
                message_kind: ATTESTATION_RESPONSE.into(),
                attestation_protocol_version: SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3
                    .into(),
                binding_identity: challenge.binding_identity.clone(),
                challenge_nonce_commitment: challenge.nonce_commitment.clone(),
                invocation_id: child.invocation_id.clone(),
                work_unit_identity: challenge.work_unit_identity.clone(),
                semantic_scope_identity: challenge.semantic_scope_identity.clone(),
                runner_principal: posture.principal_mapping_identity.clone(),
                channel_delivery: String::from("launcher_session_fd"),
                authenticated_origin: String::from("systemd-protected-launcher"),
                authority_mounts: vec![String::from("authority-system-store")],
                systemd_protected_launcher: instance,
                issuer: String::from("test-attestor"),
                audience: String::from("ota-crossing-broker"),
                issued_at: String::from("2026-08-10T00:00:00Z"),
                expires_at: String::from("2026-08-10T00:02:00Z"),
            },
            key_id: String::from("test-attestor-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("test-signature"),
        }
    }

    fn authorization_decision_for(
        request: &AuthorizationRequest,
        request_identity: &str,
        decision: AuthorizationDecision,
        revision: u64,
    ) -> SignedBrokerMessage<AuthorizationDecisionPayload> {
        SignedBrokerMessage {
            payload: AuthorizationDecisionPayload {
                message_kind: AUTHORIZATION_DECISION.into(),
                request_identity: request_identity.into(),
                binding_identity: request.binding_identity.clone(),
                authority_id: request.authority_id.clone(),
                attestation_identity: request.attestation_identity.clone(),
                challenge_nonce_commitment: request.challenge_nonce_commitment.clone(),
                work_unit_identity: request.work_unit_identity.clone(),
                contract_identity: request.contract_identity.clone(),
                semantic_scope_identity: request.semantic_scope_identity.clone(),
                decision,
                approval_reference: Some(format!("approval:{revision}")),
                broker_revision: revision,
                issued_at: String::from("2026-08-11T00:00:00Z"),
                expires_at: String::from("2026-08-11T00:01:00Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: format!("signature-{revision}"),
        }
    }

    fn admission_for(
        request: &AuthorizationRequest,
        request_identity: &str,
        decision: &SignedBrokerMessage<AuthorizationDecisionPayload>,
    ) -> AuthorizationDecisionAdmissionV1 {
        let decision_identity =
            message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), decision)
                .expect("decision identity");
        let mut admission = AuthorizationDecisionAdmissionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::AUTHORIZATION_DECISION_ADMISSION.into(),
            request_identity: request_identity.into(),
            authorization_decision_identity: decision_identity,
            binding_identity: request.binding_identity.clone(),
            attestation_identity: request.attestation_identity.clone(),
            work_unit_identity: request.work_unit_identity.clone(),
            contract_identity: request.contract_identity.clone(),
            semantic_scope_identity: request.semantic_scope_identity.clone(),
            decision: decision.payload.decision,
        };
        admission.identity =
            authorization_decision_admission_v1_identity(&admission).expect("admission identity");
        admission
    }

    #[test]
    fn v3_bridge_stops_after_exact_authorization_admission() {
        let job_profile_identity =
            systemd_job_principal_profile_identity(&systemd_job_principal_profile_v2())
                .expect("job profile identity");
        let mut mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer: UnixPrincipalIdentity {
                real_uid: 1001,
                effective_uid: 1001,
                saved_uid: 1001,
                filesystem_uid: 1001,
                real_gid: 1001,
                effective_gid: 1001,
                saved_gid: 1001,
                filesystem_gid: 1001,
            },
            execution: UnixPrincipalIdentity {
                real_uid: 1002,
                effective_uid: 1002,
                saved_uid: 1002,
                filesystem_uid: 1002,
                real_gid: 1002,
                effective_gid: 1002,
                saved_gid: 1002,
                filesystem_gid: 1002,
            },
            job_principal_profile_identity: job_profile_identity,
            launcher_session_binding_identity: identity('9'),
        };
        mapping.identity = launcher_principal_mapping_identity(&mapping).expect("mapping identity");
        let mut record = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-test"),
            request_identity: identity('3'),
            pid: 41,
            process_start_time_identity: identity('4'),
            ota_binary_identity: identity('5'),
            principal_mapping_identity: mapping.identity.clone(),
            working_directory_identity: identity('6'),
        };
        record.identity = launcher_child_process_identity(&record).expect("child identity");
        let posture = process_posture(&record, mapping.identity.as_str());
        let challenge = BrokerChallenge {
            message_kind: ota_authority_protocol::CHALLENGE_REQUEST.into(),
            protocol_version: ota_authority_protocol::PROTOCOL_VERSION_V1.into(),
            binding_identity: identity('a'),
            nonce_commitment: identity('b'),
            work_unit_identity: identity('c'),
            semantic_scope_identity: identity('d'),
            contract_identity: identity('e'),
        };
        let attestation = attestation_for(&challenge, &record, &posture);
        let attestation_identity =
            launcher_attestation_identity_v3(&attestation).expect("attestation identity");
        let authorization = AuthorizationRequest {
            message_kind: AUTHORIZATION_REQUEST.into(),
            binding_identity: challenge.binding_identity.clone(),
            authority_id: String::from("platform-release-authority"),
            attestation_identity,
            challenge_nonce_commitment: challenge.nonce_commitment.clone(),
            work_unit_identity: challenge.work_unit_identity.clone(),
            contract_identity: challenge.contract_identity.clone(),
            semantic_scope_identity: challenge.semantic_scope_identity.clone(),
            runner_principal: mapping.identity,
            actor_mode: String::from("non_agent"),
            requested_lifetime_seconds: 60,
        };
        let child_record = record.clone();
        let (launcher_session, mut core) = UnixStream::pair().expect("core session");
        let (mut proxy, mut proxy_peer) = UnixStream::pair().expect("proxy session");
        let expected_challenge = challenge.clone();
        let proxy_challenge = challenge.clone();
        let expected_attestation = attestation.clone();
        let expected_authorization = authorization.clone();
        let core_thread = std::thread::spawn(move || {
            let _: LauncherStartupContinuationV1 =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("continuation");
            write_json_frame(&mut core, &expected_challenge, Duration::from_secs(1))
                .expect("challenge");
            let observed: SignedLauncherAttestationV3 =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("attestation");
            assert_eq!(observed, expected_attestation);
            write_json_frame(&mut core, &expected_authorization, Duration::from_secs(1))
                .expect("authorization");
        });
        let proxy_thread = std::thread::spawn(move || {
            let observed: BrokerChallenge =
                read_json_frame(&mut proxy_peer, Duration::from_secs(1)).expect("proxy challenge");
            assert_eq!(observed, proxy_challenge);
            write_json_frame(&mut proxy_peer, &attestation, Duration::from_secs(1))
                .expect("proxy attestation");
            proxy_peer
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("proxy timeout");
            let mut byte = [0_u8; 1];
            assert!(proxy_peer.read(&mut byte).is_err());
        });
        let mut child = PreparedChild {
            pid: 0,
            record,
            launcher_session,
            stdout: None,
            stderr: None,
        };
        child
            .continue_and_bridge_v3_attestation(&posture, &mut proxy, Duration::from_secs(1))
            .expect("exact bridge admission");
        core_thread.join().expect("core thread");
        proxy_thread.join().expect("proxy thread");

        let mut wrong_attestation = attestation_for(&challenge, &child_record, &posture);
        wrong_attestation
            .payload
            .systemd_protected_launcher
            .instance_v1
            .child_process_identity = identity('f');
        wrong_attestation
            .payload
            .systemd_protected_launcher
            .instance_v1
            .identity = systemd_protected_launcher_instance_v3_foundation_identity(
            &wrong_attestation
                .payload
                .systemd_protected_launcher
                .instance_v1,
        )
        .expect("substituted child instance identity");
        wrong_attestation
            .payload
            .systemd_protected_launcher
            .identity = systemd_protected_launcher_instance_v2_identity(
            &wrong_attestation.payload.systemd_protected_launcher,
        )
        .expect("substituted child complete identity");
        let (launcher_session, mut core) = UnixStream::pair().expect("wrong core session");
        let (mut proxy, mut proxy_peer) = UnixStream::pair().expect("wrong proxy session");
        let wrong_challenge = challenge.clone();
        let core_thread = std::thread::spawn(move || {
            let _: LauncherStartupContinuationV1 =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("continuation");
            write_json_frame(&mut core, &wrong_challenge, Duration::from_secs(1))
                .expect("challenge");
            core.set_read_timeout(Some(Duration::from_millis(50)))
                .expect("core timeout");
            let mut byte = [0_u8; 1];
            assert!(core.read(&mut byte).is_err());
        });
        let proxy_thread = std::thread::spawn(move || {
            let _: BrokerChallenge =
                read_json_frame(&mut proxy_peer, Duration::from_secs(1)).expect("proxy challenge");
            write_json_frame(&mut proxy_peer, &wrong_attestation, Duration::from_secs(1))
                .expect("wrong attestation");
        });
        let mut child = PreparedChild {
            pid: 0,
            record: child_record,
            launcher_session,
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            child.continue_and_bridge_v3_attestation(&posture, &mut proxy, Duration::from_secs(1),),
            Err(PreparedChildError::AttestationBridgeUnavailable)
        );
        core_thread.join().expect("wrong core thread");
        proxy_thread.join().expect("wrong proxy thread");
    }

    #[test]
    fn authorization_decision_relay_requires_exact_core_admission() {
        let request = AuthorizationRequest {
            message_kind: AUTHORIZATION_REQUEST.into(),
            binding_identity: identity('1'),
            authority_id: String::from("release"),
            attestation_identity: identity('2'),
            challenge_nonce_commitment: identity('3'),
            work_unit_identity: identity('4'),
            contract_identity: identity('5'),
            semantic_scope_identity: identity('6'),
            runner_principal: identity('7'),
            actor_mode: String::from("non_agent"),
            requested_lifetime_seconds: 60,
        };
        let request_identity =
            message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &request)
                .expect("request identity");
        let decision = authorization_decision_for(
            &request,
            &request_identity,
            AuthorizationDecision::Denied,
            1,
        );
        let admission = admission_for(&request, &request_identity, &decision);
        let (launcher_session, mut core) = UnixStream::pair().expect("core pair");
        let (mut proxy, mut broker) = UnixStream::pair().expect("broker pair");
        let expected_request = request.clone();
        let broker_decision = decision.clone();
        let broker_thread = std::thread::spawn(move || {
            let observed: AuthorizationRequest =
                read_json_frame(&mut broker, Duration::from_secs(1)).expect("broker request");
            assert_eq!(observed, expected_request);
            write_json_frame(&mut broker, &broker_decision, Duration::from_secs(1))
                .expect("broker decision");
        });
        let core_decision = decision.clone();
        let core_thread = std::thread::spawn(move || {
            let observed: SignedBrokerMessage<AuthorizationDecisionPayload> =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("core decision");
            assert_eq!(observed, core_decision);
            write_json_frame(&mut core, &admission, Duration::from_secs(1))
                .expect("core admission");
        });
        let mut child = PreparedChild {
            pid: 0,
            record: LauncherChildProcessV1 {
                schema_version: 1,
                identity: identity('8'),
                invocation_id: String::from("invocation"),
                request_identity: identity('9'),
                pid: 41,
                process_start_time_identity: identity('a'),
                ota_binary_identity: identity('b'),
                principal_mapping_identity: identity('c'),
                working_directory_identity: identity('d'),
            },
            launcher_session,
            stdout: None,
            stderr: None,
        };
        let mut recorded = Vec::new();
        let observed = child
            .relay_v3_authorization_decisions(
                &request,
                &request_identity,
                &mut proxy,
                Duration::from_secs(1),
                |evidence| {
                    recorded.push(evidence.clone());
                    Ok(())
                },
                |_| Ok(()),
                |_| Ok(()),
            )
            .expect("verified decision relay");
        assert_eq!(observed.0, AuthorizationDecision::Denied);
        assert!(observed.1.is_none());
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            authorization_decision_relay_evidence_v1_identity(&recorded[0])
                .expect("relay identity"),
            recorded[0].identity
        );
        core_thread.join().expect("core thread");
        broker_thread.join().expect("broker thread");

        let (launcher_session, mut core) = UnixStream::pair().expect("wrong core pair");
        let (mut proxy, mut broker) = UnixStream::pair().expect("wrong broker pair");
        let wrong_decision = decision.clone();
        let broker_thread = std::thread::spawn(move || {
            let _: AuthorizationRequest =
                read_json_frame(&mut broker, Duration::from_secs(1)).expect("broker request");
            write_json_frame(&mut broker, &wrong_decision, Duration::from_secs(1))
                .expect("broker decision");
        });
        let mut wrong_admission = admission_for(&request, &request_identity, &decision);
        wrong_admission.semantic_scope_identity = identity('f');
        wrong_admission.identity = authorization_decision_admission_v1_identity(&wrong_admission)
            .expect("wrong admission identity");
        let core_thread = std::thread::spawn(move || {
            let _: SignedBrokerMessage<AuthorizationDecisionPayload> =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("core decision");
            write_json_frame(&mut core, &wrong_admission, Duration::from_secs(1))
                .expect("wrong core admission");
        });
        let mut child = PreparedChild {
            pid: 0,
            record: child.record.clone(),
            launcher_session,
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            child.relay_v3_authorization_decisions(
                &request,
                &request_identity,
                &mut proxy,
                Duration::from_secs(1),
                |_| Ok(()),
                |_| Ok(()),
                |_| Ok(()),
            ),
            Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable)
        );
        core_thread.join().expect("wrong core thread");
        broker_thread.join().expect("wrong broker thread");

        let (launcher_session, mut core) = UnixStream::pair().expect("scope core pair");
        let (mut proxy, mut broker) = UnixStream::pair().expect("scope broker pair");
        let mut wrong_scope = decision.clone();
        wrong_scope.payload.semantic_scope_identity = identity('f');
        let broker_scope_decision = wrong_scope.clone();
        let broker_thread = std::thread::spawn(move || {
            let _: AuthorizationRequest =
                read_json_frame(&mut broker, Duration::from_secs(1)).expect("broker request");
            write_json_frame(&mut broker, &broker_scope_decision, Duration::from_secs(1))
                .expect("wrong-scope broker decision");
        });
        let core_thread = std::thread::spawn(move || {
            let observed: SignedBrokerMessage<AuthorizationDecisionPayload> =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("relayed decision");
            assert_eq!(observed, wrong_scope);
            // Core rejection is represented by closing the protected channel without an admission.
        });
        let mut child = PreparedChild {
            pid: 0,
            record: child.record.clone(),
            launcher_session,
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            child.relay_v3_authorization_decisions(
                &request,
                &request_identity,
                &mut proxy,
                Duration::from_secs(1),
                |_| Ok(()),
                |_| Ok(()),
                |_| Ok(()),
            ),
            Err(PreparedChildError::AuthorizationDecisionBridgeUnavailable)
        );
        core_thread.join().expect("scope core thread");
        broker_thread.join().expect("scope broker thread");
    }

    #[test]
    fn consumed_lease_requires_and_emits_launcher_persistence() {
        let request = AuthorizationRequest {
            message_kind: AUTHORIZATION_REQUEST.into(),
            binding_identity: identity('1'),
            authority_id: String::from("release"),
            attestation_identity: identity('2'),
            challenge_nonce_commitment: identity('3'),
            work_unit_identity: identity('4'),
            contract_identity: identity('5'),
            semantic_scope_identity: identity('6'),
            runner_principal: identity('7'),
            actor_mode: String::from("non_agent"),
            requested_lifetime_seconds: 60,
        };
        let request_identity =
            message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &request)
                .expect("request identity");
        let decision = authorization_decision_for(
            &request,
            &request_identity,
            AuthorizationDecision::Allowed,
            1,
        );
        let decision_identity =
            message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), &decision)
                .expect("decision identity");
        let decision_admission = admission_for(&request, &request_identity, &decision);
        let lease = SignedBrokerMessage {
            payload: PreparedLeasePayload {
                message_kind: LEASE_ISSUANCE.into(),
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
                issued_at: String::from("2026-08-12T00:00:00Z"),
                expires_at: String::from("2026-08-12T00:01:00Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("lease-signature"),
        };
        let lease_identity = message_identity(
            ota_authority_protocol::LEASE_ISSUANCE_DOMAIN_V1.as_bytes(),
            &lease,
        )
        .expect("lease identity");
        let consume = LeaseConsumeRequest {
            message_kind: LEASE_CONSUME.into(),
            binding_identity: request.binding_identity.clone(),
            lease_identity: lease_identity.clone(),
            challenge_nonce_commitment: request.challenge_nonce_commitment.clone(),
            work_unit_identity: request.work_unit_identity.clone(),
            crossing_transaction_id: String::from("crossing-1"),
            crossing_transaction_identity: identity('8'),
        };
        let consume_identity = message_identity(
            ota_authority_protocol::LEASE_CONSUME_DOMAIN_V1.as_bytes(),
            &consume,
        )
        .expect("consume identity");
        let consume_response = SignedBrokerMessage {
            payload: LeaseConsumeResponsePayload {
                message_kind: LEASE_CONSUME_RESPONSE.into(),
                consume_request_identity: consume_identity.clone(),
                binding_identity: consume.binding_identity.clone(),
                lease_identity: lease_identity.clone(),
                challenge_nonce_commitment: consume.challenge_nonce_commitment.clone(),
                work_unit_identity: consume.work_unit_identity.clone(),
                crossing_transaction_id: consume.crossing_transaction_id.clone(),
                crossing_transaction_identity: consume.crossing_transaction_identity.clone(),
                state: LeaseConsumeState::Consumed,
                broker_revision: 2,
                consumed_at: String::from("2026-08-12T00:00:01Z"),
            },
            key_id: String::from("broker-key"),
            algorithm: String::from("ed25519"),
            signature: String::from("consume-signature"),
        };
        let response_identity = message_identity(
            ota_authority_protocol::LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
            &consume_response,
        )
        .expect("response identity");
        let mut consumption_admission = LeaseConsumptionAdmissionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::LEASE_CONSUMPTION_ADMISSION.into(),
            binding_identity: consume.binding_identity.clone(),
            prepared_lease_identity: lease_identity,
            consume_request_identity: consume_identity,
            consume_response_identity: response_identity,
            work_unit_identity: consume.work_unit_identity.clone(),
            crossing_transaction_id: consume.crossing_transaction_id.clone(),
            crossing_transaction_identity: consume.crossing_transaction_identity.clone(),
        };
        consumption_admission.identity =
            lease_consumption_admission_v1_identity(&consumption_admission)
                .expect("admission identity");

        let (launcher_session, mut core) = UnixStream::pair().expect("core pair");
        let (mut proxy, mut broker) = UnixStream::pair().expect("broker pair");
        let broker_request = request.clone();
        let broker_decision = decision.clone();
        let broker_lease = lease.clone();
        let broker_consume = consume.clone();
        let broker_response = consume_response.clone();
        let broker_thread = std::thread::spawn(move || {
            assert_eq!(
                read_json_frame::<AuthorizationRequest>(&mut broker, Duration::from_secs(1))
                    .expect("request"),
                broker_request
            );
            write_json_frame(&mut broker, &broker_decision, Duration::from_secs(1))
                .expect("decision");
            write_json_frame(&mut broker, &broker_lease, Duration::from_secs(1)).expect("lease");
            assert_eq!(
                read_json_frame::<LeaseConsumeRequest>(&mut broker, Duration::from_secs(1))
                    .expect("consume"),
                broker_consume
            );
            write_json_frame(&mut broker, &broker_response, Duration::from_secs(1))
                .expect("response");
        });
        let core_decision = decision.clone();
        let core_lease = lease.clone();
        let core_consume = consume.clone();
        let core_response = consume_response.clone();
        let core_admission = consumption_admission.clone();
        let core_thread = std::thread::spawn(move || {
            assert_eq!(
                read_json_frame::<SignedBrokerMessage<AuthorizationDecisionPayload>>(
                    &mut core,
                    Duration::from_secs(1)
                )
                .expect("decision"),
                core_decision
            );
            write_json_frame(&mut core, &decision_admission, Duration::from_secs(1))
                .expect("decision admission");
            assert_eq!(
                read_json_frame::<SignedBrokerMessage<PreparedLeasePayload>>(
                    &mut core,
                    Duration::from_secs(1)
                )
                .expect("lease"),
                core_lease
            );
            write_json_frame(&mut core, &core_consume, Duration::from_secs(1)).expect("consume");
            let intent_persistence: LeaseConsumptionIntentPersistenceV1 =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("intent persistence");
            assert_eq!(
                lease_consumption_intent_persistence_v1_identity(&intent_persistence)
                    .expect("intent persistence identity"),
                intent_persistence.identity
            );
            assert_eq!(
                read_json_frame::<SignedBrokerMessage<LeaseConsumeResponsePayload>>(
                    &mut core,
                    Duration::from_secs(1)
                )
                .expect("response"),
                core_response
            );
            write_json_frame(&mut core, &core_admission, Duration::from_secs(1))
                .expect("consumption admission");
            let persistence: LeaseConsumptionPersistenceV1 =
                read_json_frame(&mut core, Duration::from_secs(1)).expect("persistence");
            assert_eq!(
                persistence.consumption_admission_identity,
                core_admission.identity
            );
            assert_eq!(
                lease_consumption_persistence_v1_identity(&persistence)
                    .expect("persistence identity"),
                persistence.identity
            );
        });
        let mut child = PreparedChild {
            pid: 0,
            record: LauncherChildProcessV1 {
                schema_version: 1,
                identity: identity('9'),
                invocation_id: String::from("invocation"),
                request_identity: identity('a'),
                pid: 41,
                process_start_time_identity: identity('b'),
                ota_binary_identity: identity('c'),
                principal_mapping_identity: identity('d'),
                working_directory_identity: identity('e'),
            },
            launcher_session,
            stdout: None,
            stderr: None,
        };
        let mut consumptions = Vec::new();
        let result = child
            .relay_v3_authorization_decisions(
                &request,
                &request_identity,
                &mut proxy,
                Duration::from_secs(1),
                |_| Ok(()),
                |evidence| {
                    consumptions.push(evidence.clone());
                    Ok(())
                },
                |_| Ok(()),
            )
            .expect("consumed lease relay");
        assert_eq!(result.0, AuthorizationDecision::Allowed);
        assert_eq!(result.1, consumptions.first().cloned());
        assert_eq!(consumptions.len(), 1);
        assert_eq!(
            lease_consumption_relay_evidence_v1_identity(&consumptions[0]).expect("relay identity"),
            consumptions[0].identity
        );
        core_thread.join().expect("core thread");
        broker_thread.join().expect("broker thread");

        let consumption = consumptions.pop().expect("consumption evidence");
        let (stdout, child_stdout) = pipe_cloexec().expect("stdout pipe");
        let (stderr, child_stderr) = pipe_cloexec().expect("stderr pipe");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork selected child");
        if pid == 0 {
            drop(stdout);
            drop(stderr);
            let stdout_payload = b"selected stdout\n";
            let stderr_payload = b"selected stderr\n";
            unsafe {
                libc::write(
                    child_stdout.as_raw_fd(),
                    stdout_payload.as_ptr().cast(),
                    stdout_payload.len(),
                );
                libc::write(
                    child_stderr.as_raw_fd(),
                    stderr_payload.as_ptr().cast(),
                    stderr_payload.len(),
                );
                libc::_exit(0);
            }
        }
        drop(child_stdout);
        drop(child_stderr);
        let (launcher_session, mut core) = UnixStream::pair().expect("completion session");
        let (client, mut pressure_client) = UnixStream::pair().expect("output session");
        let mut completion = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: String::from("invocation"),
            lease_consumption_admission_identity: consumption.admission.identity.clone(),
            work_unit_identity: consumption.admission.work_unit_identity.clone(),
            crossing_transaction_id: consumption.admission.crossing_transaction_id.clone(),
            pending_crossing_transaction_identity: consumption
                .admission
                .crossing_transaction_identity
                .clone(),
            crossing_transaction_identity: identity('f'),
            receipt_archive_identity: Some(identity('e')),
            outcome: ota_authority_protocol::LauncherExecutionOutcomeV1::Completed,
            exit_code: Some(0),
            receipt_status: String::from("archived"),
        };
        completion.identity =
            launcher_execution_completion_v1_identity(&completion).expect("completion identity");
        let expected_completion = completion.clone();
        let core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut core, &completion).expect("send completion");
            let persistence: LauncherExecutionCompletionPersistenceV1 =
                read_json_frame_blocking(&mut core).expect("completion persistence");
            assert_eq!(persistence.completion_identity, completion.identity);
        });
        let mut child = PreparedChild {
            pid,
            record: LauncherChildProcessV1 {
                schema_version: 1,
                identity: identity('9'),
                invocation_id: String::from("invocation"),
                request_identity: identity('a'),
                pid: pid as u32,
                process_start_time_identity: identity('b'),
                ota_binary_identity: identity('c'),
                principal_mapping_identity: identity('d'),
                working_directory_identity: identity('e'),
            },
            launcher_session,
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        let mut persisted = Vec::new();
        let (observed_completion, observed_exit) = child
            .relay_selected_execution(&client, &consumption, |completion| {
                persisted.push(completion);
                Ok(())
            })
            .expect("selected execution relay");
        assert_eq!(observed_completion, expected_completion);
        assert_eq!(observed_exit, Some(0));
        assert_eq!(persisted, vec![expected_completion]);
        core_thread.join().expect("completion core thread");
        let first: LauncherOutputFrameV1 =
            read_json_frame_blocking(&mut pressure_client).expect("first output");
        let second: LauncherOutputFrameV1 =
            read_json_frame_blocking(&mut pressure_client).expect("second output");
        assert_eq!((first.sequence, second.sequence), (0, 1));
        assert_ne!(first.stream, second.stream);
    }

    #[test]
    fn selected_child_signal_is_observed_as_canonical_exit_code() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork selected child");
        if pid == 0 {
            unsafe {
                libc::pause();
                libc::_exit(0);
            }
        }
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
        let (launcher_session, _core) = UnixStream::pair().expect("completion session");
        let mut child = PreparedChild {
            pid,
            record: LauncherChildProcessV1 {
                schema_version: 1,
                identity: identity('1'),
                invocation_id: String::from("invocation"),
                request_identity: identity('2'),
                pid: pid as u32,
                process_start_time_identity: identity('3'),
                ota_binary_identity: identity('4'),
                principal_mapping_identity: identity('5'),
                working_directory_identity: identity('6'),
            },
            launcher_session,
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            child
                .wait_and_reap_selected_child()
                .expect("reap signalled child"),
            Some(143)
        );
    }

    #[test]
    fn process_posture_frame_is_bounded_and_exactly_child_bound() {
        let mapping = identity('1');
        let child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: identity('2'),
            invocation_id: String::from("invocation-test"),
            request_identity: identity('3'),
            pid: 41,
            process_start_time_identity: identity('4'),
            ota_binary_identity: identity('5'),
            principal_mapping_identity: mapping.clone(),
            working_directory_identity: identity('6'),
        };
        let posture = process_posture(&child, mapping.as_str());
        let (mut writer, mut reader) = UnixStream::pair().expect("posture session");
        let payload = serde_json::to_vec(&posture).expect("posture JSON");
        writer
            .write_all(&encode_frame(&payload).expect("posture frame"))
            .expect("write posture");
        let observed =
            receive_process_posture(&mut reader, Duration::from_secs(1)).expect("receive posture");
        validate_process_posture(&observed, &child, mapping.as_str())
            .expect("exact posture accepted");

        let mut wrong_mapping = observed.clone();
        wrong_mapping.principal_mapping_identity = identity('7');
        wrong_mapping.identity =
            ota_process_posture_identity(&wrong_mapping).expect("changed posture identity");
        assert_eq!(
            validate_process_posture(&wrong_mapping, &child, mapping.as_str()),
            Err(PreparedChildError::PostureMismatch)
        );

        let mut invalid_controls = observed;
        invalid_controls.dumpable = 1;
        assert_eq!(
            validate_process_posture(&invalid_controls, &child, mapping.as_str()),
            Err(PreparedChildError::PostureMismatch)
        );
    }

    #[test]
    fn process_posture_reader_rejects_empty_and_oversized_frames() {
        for header in [0_u32, (MAX_FRAME_BYTES as u32).saturating_add(1)] {
            let (mut writer, mut reader) = UnixStream::pair().expect("posture session");
            writer
                .write_all(&header.to_be_bytes())
                .expect("write invalid header");
            assert_eq!(
                receive_process_posture(&mut reader, Duration::from_secs(1)),
                Err(PreparedChildError::PostureUnavailable)
            );
        }
    }

    #[test]
    fn child_exit_before_stop_is_already_reaped() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork child");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        assert_eq!(
            wait_for_stop(child, Duration::from_secs(5)),
            Err(PreparedChildError::ExitedBeforeStop)
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn root_prepares_stopped_child_and_refuses_missing_posture_after_resume() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .expect("permissions");
        let repository_file = File::open(temporary.path()).expect("repository descriptor");
        let metadata = repository_file.metadata().expect("repository metadata");
        let mut working = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: temporary.path().to_string_lossy().into_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        working.identity = launcher_working_directory_identity(&working).expect("working identity");
        let repository = OpenedRepositoryDirectory {
            descriptor: repository_file.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
        };
        let executable = File::open("/bin/true").expect("test executable");
        let config = SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: identity('a'),
            adapter: ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            socket_path: PathBuf::from("/run/ota/authority-launcher.sock"),
            socket_group_gid: 1001,
            ota_binary: PathBuf::from("/bin/true"),
            environment: BTreeMap::from([(String::from("PATH"), String::from("/usr/bin"))]),
            allowed_repository_roots: vec![temporary.path().into()],
            mappings: Vec::new(),
            broker_proxy_socket: PathBuf::from("/run/ota/broker-proxy.sock"),
            broker_proxy_peer: crate::config::SessionPeer { uid: 0, gid: 0 },
            service_unit_identity: identity('b'),
            socket_unit_identity: identity('c'),
            ota_binary_identity: identity('d'),
            broker_proxy_identity: identity('e'),
            broker_proxy_executable_identity: identity('1'),
            attestor_key_set_identity: identity('f'),
            attestation_claims: None,
            maximum_request_bytes: 4096,
            maximum_active_sessions: 1,
            maximum_startup_seconds: 5,
            maximum_terminal_wait_seconds: 30,
        };
        let mut child = prepare_stopped_child(
            &config,
            &executable,
            &repository,
            &RunAs {
                uid: 65_534,
                gid: 65_534,
            },
            &PreparedChildBinding {
                invocation_id: "invocation-test",
                request_identity: identity('2').as_str(),
                principal_mapping_identity: identity('1').as_str(),
                working_directory_identity: working.identity.as_str(),
            },
            &[String::from("run"), String::from("verify")],
        )
        .expect("prepare stopped child");
        assert!(PathBuf::from(format!("/proc/{}", child.record.pid)).exists());
        child.terminate_and_reap().expect("cleanup child");
        assert!(!PathBuf::from(format!("/proc/{}", child.record.pid)).exists());

        let mut postureless = prepare_stopped_child(
            &config,
            &executable,
            &repository,
            &RunAs {
                uid: 65_534,
                gid: 65_534,
            },
            &PreparedChildBinding {
                invocation_id: "invocation-postureless",
                request_identity: identity('7').as_str(),
                principal_mapping_identity: identity('1').as_str(),
                working_directory_identity: working.identity.as_str(),
            },
            &[String::from("run"), String::from("verify")],
        )
        .expect("prepare postureless child");
        assert_eq!(unsafe { libc::kill(postureless.pid, libc::SIGCONT) }, 0);
        assert_eq!(
            postureless.receive_process_posture_after_resume(
                identity('1').as_str(),
                Duration::from_secs(5),
            ),
            Err(PreparedChildError::PostureUnavailable),
            "the exact child must resume successfully and fail only when no posture arrives"
        );
        postureless
            .terminate_and_reap()
            .expect("cleanup postureless child");
        assert!(!PathBuf::from(format!("/proc/{}", postureless.record.pid)).exists());

        let abandoned = prepare_stopped_child(
            &config,
            &executable,
            &repository,
            &RunAs {
                uid: 65_534,
                gid: 65_534,
            },
            &PreparedChildBinding {
                invocation_id: "invocation-recovery",
                request_identity: identity('3').as_str(),
                principal_mapping_identity: identity('1').as_str(),
                working_directory_identity: working.identity.as_str(),
            },
            &[String::from("run"), String::from("verify")],
        )
        .expect("prepare abandoned child");
        let abandoned_record = abandoned.record.clone();
        abandoned.abandon_for_recovery();
        match terminate_recorded_child(&abandoned_record, Duration::from_secs(5)) {
            Ok(()) => {}
            Err(PreparedChildError::CleanupFailed) if !pidfd_available() => {
                kill_and_reap(abandoned_record.pid as libc::pid_t).expect("test fallback cleanup");
            }
            Err(error) => panic!("terminate recorded child: {error}"),
        }
        assert!(!PathBuf::from(format!("/proc/{}", abandoned_record.pid)).exists());
    }

    fn pidfd_available() -> bool {
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        if descriptor < 0 {
            return false;
        }
        unsafe { libc::close(descriptor as RawFd) };
        true
    }
}
