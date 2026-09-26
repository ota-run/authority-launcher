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
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ota_authority_protocol::{
    ATTESTATION_RESPONSE, AUTHORIZATION_DECISION, AUTHORIZATION_DECISION_DOMAIN_V1,
    AUTHORIZATION_REQUEST, AUTHORIZATION_REQUEST_DOMAIN_V1, AuthorizationDecision,
    AuthorizationDecisionAdmissionV1, AuthorizationDecisionPayload,
    AuthorizationDecisionRelayEvidenceV1, AuthorizationRequest, BrokerChallenge,
    LAUNCHER_EXECUTION_COMPLETION, LAUNCHER_EXECUTION_COMPLETION_PERSISTENCE, LAUNCHER_OUTPUT,
    LEASE_CONSUME, LEASE_CONSUME_RESPONSE, LEASE_CONSUMPTION_INTENT_PERSISTENCE,
    LEASE_CONSUMPTION_PERSISTENCE, LEASE_ISSUANCE, LauncherChildProcessV1,
    LauncherExecutionCompletionPersistenceV1, LauncherExecutionCompletionV1, LauncherOutputFrameV1,
    LauncherOutputStreamV1, LauncherStartupContinuationV1, LeaseConsumeRequest,
    LeaseConsumeResponsePayload, LeaseConsumptionAdmissionV1, LeaseConsumptionIntentPersistenceV1,
    LeaseConsumptionIntentRelayEvidenceV1, LeaseConsumptionPersistenceV1,
    LeaseConsumptionRelayEvidenceV1, MAX_FRAME_BYTES, OtaProcessPostureV1,
    PROTECTED_AUTHORITY_SNAPSHOT_REQUEST, PROTECTED_AUTHORITY_SNAPSHOT_REQUEST_V2,
    PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST,
    PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST,
    PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2,
    PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3,
    PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4, PreparedLeasePayload,
    ProtectedAuthoritySnapshotRequestV1, ProtectedAuthoritySnapshotRequestV2,
    ProtectedAuthoritySnapshotResponseV1, ProtectedAuthoritySnapshotResponseV2,
    ProtectedLauncherCapabilityObservationRequestV1,
    ProtectedLauncherCapabilityObservationResponseV1,
    ProtectedLauncherSecretDeliveryTransactionBindingRequestV1,
    ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
    ProtectedLauncherSecretDeliveryTransactionBindingRequestV3,
    ProtectedLauncherSecretDeliveryTransactionBindingRequestV4,
    ProtectedLauncherSecretDeliveryTransactionBindingResponseV1,
    ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
    ProtectedLauncherSecretDeliveryTransactionBindingResponseV3,
    ProtectedLauncherSecretDeliveryTransactionBindingResponseV4,
    ProtectedSameChildCapabilityPreludeV1, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1,
    SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3, SignedBrokerMessage,
    SignedLauncherAttestationV3, authorization_decision_admission_v1_identity,
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
use sha2::{Digest, Sha256};
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
    selected_session_object: DescriptorObject,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretDeliveryRelayState {
    AwaitPreludeOrLegacyOrCompletion,
    PreludeResponded,
    SnapshotResponded,
    SnapshotV2Responded,
    LegacyBound,
    V2Bound,
    V3Bound,
    V4Bound,
}

fn advance_secret_delivery_relay_state(
    state: SecretDeliveryRelayState,
    message_kind: Option<&str>,
) -> Result<SecretDeliveryRelayState, PreparedChildError> {
    match (state, message_kind) {
        (
            SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
            Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST),
        ) => Ok(SecretDeliveryRelayState::PreludeResponded),
        (
            SecretDeliveryRelayState::PreludeResponded,
            Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST),
        ) => Ok(SecretDeliveryRelayState::SnapshotResponded),
        (
            SecretDeliveryRelayState::PreludeResponded,
            Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST_V2),
        ) => Ok(SecretDeliveryRelayState::SnapshotV2Responded),
        (
            SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
            Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST),
        ) => Ok(SecretDeliveryRelayState::LegacyBound),
        (
            SecretDeliveryRelayState::SnapshotResponded,
            Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2),
        ) => Ok(SecretDeliveryRelayState::V2Bound),
        (
            SecretDeliveryRelayState::SnapshotResponded,
            Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3),
        ) => Ok(SecretDeliveryRelayState::V3Bound),
        (
            SecretDeliveryRelayState::SnapshotV2Responded,
            Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4),
        ) => Ok(SecretDeliveryRelayState::V4Bound),
        (_, Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST))
        | (_, Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST))
        | (_, Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST_V2))
        | (_, Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST))
        | (_, Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2))
        | (_, Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3)) => {
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        }
        (_, Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4)) => {
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        }
        _ => Ok(state),
    }
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
    ) -> Result<(AuthorizationRequest, String, LauncherStartupContinuationV1), PreparedChildError>
    {
        let mut continuation = LauncherStartupContinuationV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::LAUNCHER_STARTUP_CONTINUATION.into(),
            invocation_id: self.record.invocation_id.clone(),
            launcher_request_identity: self.record.request_identity.clone(),
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
        Ok((authorization, request_identity, continuation))
    }

    fn receive_process_posture_after_resume(
        &mut self,
        expected_principal_mapping_identity: &str,
        timeout: Duration,
    ) -> Result<OtaProcessPostureV1, PreparedChildError> {
        let posture = receive_process_posture(&mut self.launcher_session, timeout)?;
        validate_process_posture(&posture, &self.record, expected_principal_mapping_identity)?;
        verify_running_child_identity(self.pid, &self.record, self.selected_session_object)?;
        pressure_v3_stage("selected_child_runtime_identity_reconciled");
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relay_selected_execution_with_secret_binding(
        &mut self,
        client: &UnixStream,
        consumption: &LeaseConsumptionRelayEvidenceV1,
        observe_same_child_capability: impl FnOnce(
            &ProtectedLauncherCapabilityObservationRequestV1,
            &UnixStream,
        ) -> Result<
            (
                ProtectedLauncherCapabilityObservationResponseV1,
                ProtectedSameChildCapabilityPreludeV1,
            ),
            PreparedChildError,
        >,
        respond_authority_snapshot: impl FnOnce(
            &ProtectedAuthoritySnapshotRequestV1,
            &UnixStream,
        ) -> Result<
            ProtectedAuthoritySnapshotResponseV1,
            PreparedChildError,
        >,
        respond_authority_snapshot_v2: impl FnOnce(
            &ProtectedAuthoritySnapshotRequestV2,
            &UnixStream,
        ) -> Result<
            ProtectedAuthoritySnapshotResponseV2,
            PreparedChildError,
        >,
        bind_secret_delivery: impl FnOnce(
            &ProtectedLauncherSecretDeliveryTransactionBindingRequestV1,
            &UnixStream,
        ) -> Result<
            ProtectedLauncherSecretDeliveryTransactionBindingResponseV1,
            PreparedChildError,
        >,
        bind_snapshot_secret_delivery: impl FnOnce(
            &ProtectedLauncherSecretDeliveryTransactionBindingRequestV2,
            &UnixStream,
        ) -> Result<
            ProtectedLauncherSecretDeliveryTransactionBindingResponseV2,
            PreparedChildError,
        >,
        bind_snapshot_secret_delivery_v3: impl FnOnce(
            &ProtectedLauncherSecretDeliveryTransactionBindingRequestV3,
            &UnixStream,
        ) -> Result<
            ProtectedLauncherSecretDeliveryTransactionBindingResponseV3,
            PreparedChildError,
        >,
        bind_snapshot_secret_delivery_v4: impl FnOnce(
            &ProtectedLauncherSecretDeliveryTransactionBindingRequestV4,
            &UnixStream,
        ) -> Result<
            ProtectedLauncherSecretDeliveryTransactionBindingResponseV4,
            PreparedChildError,
        >,
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

        let mut relay_state = SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion;
        let first = read_json_frame_blocking::<serde_json::Value>(&mut self.launcher_session)
            .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
        let message_kind = first
            .get("message_kind")
            .and_then(serde_json::Value::as_str);
        let completion: LauncherExecutionCompletionV1 = match (relay_state, message_kind) {
            (
                SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST),
            ) => {
                relay_state = advance_secret_delivery_relay_state(relay_state, message_kind)?;
                pressure_v3_stage("secret_binding_v1_request_received");
                let request = serde_json::from_value(first)
                    .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                let response = bind_secret_delivery(&request, &self.launcher_session)?;
                write_json_frame_blocking(&mut self.launcher_session, &response)
                    .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                pressure_v3_stage("secret_binding_v1_response_sent");
                let value = read_json_frame_blocking(&mut self.launcher_session)
                    .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
                parse_completion_for_state(value, relay_state)?
            }
            (
                SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
                Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST),
            ) => {
                relay_state = advance_secret_delivery_relay_state(relay_state, message_kind)?;
                pressure_v3_stage("capability_observation_request_received");
                let request = serde_json::from_value(first)
                    .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                let (response, prelude) =
                    observe_same_child_capability(&request, &self.launcher_session).inspect_err(
                        |_| {
                            pressure_v3_stage("capability_observation_refused");
                        },
                    )?;
                write_json_frame_blocking(&mut self.launcher_session, &response)
                    .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                write_json_frame_blocking(&mut self.launcher_session, &prelude)
                    .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                pressure_v3_stage("capability_observation_response_sent");
                let snapshot: serde_json::Value =
                    read_json_frame_blocking(&mut self.launcher_session)
                        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
                pressure_v3_stage("selected_child_inbound_frame_2_received");
                if let Some(completion) =
                    parse_pre_binding_refusal_completion(snapshot.clone(), relay_state)?
                {
                    pressure_v3_stage("pre_snapshot_refusal_completion_received");
                    completion
                } else {
                    relay_state = advance_secret_delivery_relay_state(
                        relay_state,
                        snapshot
                            .get("message_kind")
                            .and_then(serde_json::Value::as_str),
                    )?;
                    pressure_v3_stage("authority_snapshot_request_received");
                    let response = match relay_state {
                        SecretDeliveryRelayState::SnapshotResponded => {
                            #[cfg(feature = "systemd-pressure-faults")]
                            let request = serde_json::from_value(snapshot.clone())
                                .inspect_err(|_| {
                                    pressure_v3_stage("authority_snapshot_request_invalid");
                                    pressure_v3_stage(authority_snapshot_request_shape_marker(
                                        &snapshot,
                                    ));
                                })
                                .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                            #[cfg(not(feature = "systemd-pressure-faults"))]
                            let request = serde_json::from_value(snapshot)
                                .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                            serde_json::to_value(
                                respond_authority_snapshot(&request, &self.launcher_session)
                                    .inspect_err(|_| {
                                        pressure_v3_stage("authority_snapshot_refused")
                                    })?,
                            )
                            .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?
                        }
                        SecretDeliveryRelayState::SnapshotV2Responded => {
                            let request: ProtectedAuthoritySnapshotRequestV2 =
                                serde_json::from_value(snapshot).map_err(|_| {
                                    PreparedChildError::AuthorizationAdmissionMismatch
                                })?;
                            serde_json::to_value(
                                respond_authority_snapshot_v2(&request, &self.launcher_session)
                                    .inspect_err(|_| {
                                        pressure_v3_stage("authority_snapshot_v2_refused")
                                    })?,
                            )
                            .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?
                        }
                        _ => return Err(PreparedChildError::AuthorizationAdmissionMismatch),
                    };
                    write_json_frame_blocking(&mut self.launcher_session, &response)
                        .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                    pressure_v3_stage("authority_snapshot_response_sent");
                    let binding: serde_json::Value =
                        read_json_frame_blocking(&mut self.launcher_session)
                            .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
                    if let Some(completion) =
                        parse_pre_binding_refusal_completion(binding.clone(), relay_state)?
                    {
                        pressure_v3_stage("pre_binding_refusal_completion_received");
                        completion
                    } else {
                        relay_state = advance_secret_delivery_relay_state(
                            relay_state,
                            binding
                                .get("message_kind")
                                .and_then(serde_json::Value::as_str),
                        )?;
                        let binding_kind = binding
                            .get("message_kind")
                            .and_then(serde_json::Value::as_str);
                        let (response, response_sent_marker) = match binding_kind {
                            Some(
                                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2,
                            ) => {
                                pressure_v3_stage("secret_binding_v2_request_received");
                                let request = serde_json::from_value(binding).map_err(|_| {
                                    PreparedChildError::AuthorizationAdmissionMismatch
                                })?;
                                let response =
                                    bind_snapshot_secret_delivery(&request, &self.launcher_session)
                                        .inspect_err(|_| {
                                            pressure_v3_stage("secret_binding_v2_refused");
                                        })?;
                                (
                                    serde_json::to_value(response).map_err(|_| {
                                        PreparedChildError::AuthorizationAdmissionMismatch
                                    })?,
                                    "secret_binding_v2_response_sent",
                                )
                            }
                            Some(
                                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3,
                            ) => {
                                pressure_v3_stage("secret_binding_v3_request_received");
                                let request = serde_json::from_value(binding).map_err(|_| {
                                    PreparedChildError::AuthorizationAdmissionMismatch
                                })?;
                                let response = bind_snapshot_secret_delivery_v3(
                                    &request,
                                    &self.launcher_session,
                                )
                                .inspect_err(|_| {
                                    pressure_v3_stage("secret_binding_v3_refused");
                                })?;
                                (
                                    serde_json::to_value(response).map_err(|_| {
                                        PreparedChildError::AuthorizationAdmissionMismatch
                                    })?,
                                    "secret_binding_v3_response_sent",
                                )
                            }
                            Some(
                                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4,
                            ) => {
                                let request = serde_json::from_value(binding).map_err(|_| {
                                    PreparedChildError::AuthorizationAdmissionMismatch
                                })?;
                                let response = bind_snapshot_secret_delivery_v4(
                                    &request,
                                    &self.launcher_session,
                                )?;
                                (
                                    serde_json::to_value(response).map_err(|_| {
                                        PreparedChildError::AuthorizationAdmissionMismatch
                                    })?,
                                    "secret_binding_v4_response_sent",
                                )
                            }
                            _ => return Err(PreparedChildError::AuthorizationAdmissionMismatch),
                        };
                        write_json_frame_blocking(&mut self.launcher_session, &response)
                            .map_err(|_| PreparedChildError::AuthorizationAdmissionMismatch)?;
                        pressure_v3_stage(response_sent_marker);
                        let value = read_json_frame_blocking(&mut self.launcher_session)
                            .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
                        parse_completion_for_state(value, relay_state)?
                    }
                }
            }
            (
                SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2),
            ) => {
                return Err(PreparedChildError::AuthorizationAdmissionMismatch);
            }
            (
                SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3),
            ) => {
                return Err(PreparedChildError::AuthorizationAdmissionMismatch);
            }
            (
                SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4),
            ) => {
                return Err(PreparedChildError::AuthorizationAdmissionMismatch);
            }
            (SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion, _) => {
                serde_json::from_value(first)
                    .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?
            }
            _ => return Err(PreparedChildError::AuthorizationAdmissionMismatch),
        };
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

fn parse_completion_for_state(
    value: serde_json::Value,
    state: SecretDeliveryRelayState,
) -> Result<LauncherExecutionCompletionV1, PreparedChildError> {
    if !matches!(
        state,
        SecretDeliveryRelayState::LegacyBound
            | SecretDeliveryRelayState::V2Bound
            | SecretDeliveryRelayState::V3Bound
            | SecretDeliveryRelayState::V4Bound
    ) {
        return Err(PreparedChildError::AuthorizationAdmissionMismatch);
    }
    match value
        .get("message_kind")
        .and_then(serde_json::Value::as_str)
    {
        Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST)
        | Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST_V2)
        | Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST)
        | Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST)
        | Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2)
        | Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3) => {
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        }
        Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4) => {
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        }
        _ => serde_json::from_value(value)
            .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable),
    }
}

fn parse_pre_binding_refusal_completion(
    value: serde_json::Value,
    state: SecretDeliveryRelayState,
) -> Result<Option<LauncherExecutionCompletionV1>, PreparedChildError> {
    if value
        .get("message_kind")
        .and_then(serde_json::Value::as_str)
        != Some(LAUNCHER_EXECUTION_COMPLETION)
    {
        return Ok(None);
    }
    if !matches!(
        state,
        SecretDeliveryRelayState::PreludeResponded
            | SecretDeliveryRelayState::SnapshotResponded
            | SecretDeliveryRelayState::SnapshotV2Responded
    ) {
        return Err(PreparedChildError::AuthorizationAdmissionMismatch);
    }
    let completion: LauncherExecutionCompletionV1 = serde_json::from_value(value)
        .map_err(|_| PreparedChildError::ExecutionCompletionUnavailable)?;
    if completion.outcome != ota_authority_protocol::LauncherExecutionOutcomeV1::Failed {
        return Err(PreparedChildError::AuthorizationAdmissionMismatch);
    }
    Ok(Some(completion))
}

fn pressure_v3_stage(stage: &'static str) {
    #[cfg(feature = "systemd-pressure-faults")]
    eprintln!("ota-authority-launcher: bounded pressure v3 stage={stage}");
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = stage;
}

/// Classifies only the closed wire shape of a refused snapshot request. It must never emit
/// request values, identities, or decoder text from the protected channel.
#[cfg(feature = "systemd-pressure-faults")]
fn authority_snapshot_request_shape_marker(value: &serde_json::Value) -> &'static str {
    const REQUEST_FIELDS: [&str; 10] = [
        "schema_version",
        "message_kind",
        "identity",
        "challenge",
        "nonce",
        "launcher_request_identity",
        "startup_continuation_identity",
        "session_identity",
        "contract_identity",
        "selected_execution_graph_identity",
    ];
    let Some(request) = value.as_object() else {
        return "authority_snapshot_request_not_object";
    };
    const SNAPSHOT_CHALLENGE_FIELDS: [&str; 6] = [
        "schema_version",
        "message_kind",
        "identity",
        "nonce_commitment",
        "issued_at_unix_seconds",
        "expires_at_unix_seconds",
    ];
    const SNAPSHOT_RESPONSE_FIELDS: [&str; 6] = [
        "schema_version",
        "message_kind",
        "identity",
        "request_identity",
        "payload",
        "protected_snapshot_identity",
    ];
    let matches_fields = |fields: &[&str]| {
        request.len() == fields.len()
            && request.keys().all(|field| fields.contains(&field.as_str()))
    };
    if matches_fields(&SNAPSHOT_CHALLENGE_FIELDS) {
        return "authority_snapshot_request_matches_snapshot_challenge_root_shape";
    }
    if matches_fields(&SNAPSHOT_RESPONSE_FIELDS) {
        return "authority_snapshot_request_matches_snapshot_response_root_shape";
    }
    let has_unknown_field = request
        .keys()
        .any(|field| !REQUEST_FIELDS.contains(&field.as_str()));
    let missing = REQUEST_FIELDS
        .iter()
        .copied()
        .filter(|field| !request.contains_key(*field))
        .collect::<Vec<_>>();
    if has_unknown_field {
        return match missing.as_slice() {
            [] => "authority_snapshot_request_unknown_field_complete_required_shape",
            ["challenge"] => "authority_snapshot_request_unknown_field_missing_only_challenge",
            _ => match REQUEST_FIELDS.len() - missing.len() {
                0 => "authority_snapshot_request_unknown_field_known_field_count_0",
                1 => "authority_snapshot_request_unknown_field_known_field_count_1",
                2 => "authority_snapshot_request_unknown_field_known_field_count_2",
                3 => "authority_snapshot_request_unknown_field_known_field_count_3",
                4 => "authority_snapshot_request_unknown_field_known_field_count_4",
                5 => "authority_snapshot_request_unknown_field_known_field_count_5",
                6 => "authority_snapshot_request_unknown_field_known_field_count_6",
                7 => "authority_snapshot_request_unknown_field_known_field_count_7",
                8 => "authority_snapshot_request_unknown_field_known_field_count_8",
                _ => "authority_snapshot_request_unknown_field_known_field_count_9",
            },
        };
    }
    match missing.as_slice() {
        [] => "authority_snapshot_request_nested_or_value_invalid",
        // Field names are a closed protocol vocabulary, not protected request material.
        ["schema_version"] => "authority_snapshot_request_missing_only_schema_version",
        ["message_kind"] => "authority_snapshot_request_missing_only_message_kind",
        ["identity"] => "authority_snapshot_request_missing_only_identity",
        ["challenge"] => "authority_snapshot_request_missing_only_challenge",
        ["nonce"] => "authority_snapshot_request_missing_only_nonce",
        ["launcher_request_identity"] => {
            "authority_snapshot_request_missing_only_launcher_request_identity"
        }
        ["startup_continuation_identity"] => {
            "authority_snapshot_request_missing_only_startup_continuation_identity"
        }
        ["session_identity"] => "authority_snapshot_request_missing_only_session_identity",
        ["contract_identity"] => "authority_snapshot_request_missing_only_contract_identity",
        ["selected_execution_graph_identity"] => {
            "authority_snapshot_request_missing_only_selected_execution_graph_identity"
        }
        _ => "authority_snapshot_request_multiple_required_fields_missing",
    }
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
    let selected_session_object = descriptor_object(child_session.as_raw_fd())?;
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
            selected_session_object,
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
        selected_session_object,
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

fn verify_running_child_identity(
    pid: libc::pid_t,
    child: &LauncherChildProcessV1,
    expected_session_object: DescriptorObject,
) -> Result<(), PreparedChildError> {
    let process_start_time_identity = process_start_identity(pid).inspect_err(|_| {
        pressure_v3_stage("selected_child_runtime_start_identity_unavailable");
    })?;
    let session_metadata =
        std::fs::metadata(format!("/proc/{pid}/fd/{SYSTEMD_OTA_SESSION_DESCRIPTOR}"))
            .inspect_err(|_| {
                pressure_v3_stage("selected_child_runtime_session_metadata_unavailable");
            })
            .map_err(|_| PreparedChildError::PostureMismatch)?;
    let observed_session_object = DescriptorObject {
        device: session_metadata.dev(),
        inode: session_metadata.ino(),
        file_type: session_metadata.mode() & libc::S_IFMT,
    };
    let session_cloexec =
        descriptor_cloexec(pid, SYSTEMD_OTA_SESSION_DESCRIPTOR).inspect_err(|_| {
            pressure_v3_stage("selected_child_runtime_session_flags_unavailable");
        })?;
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/exe"))
        .inspect_err(|_| {
            pressure_v3_stage("selected_child_runtime_executable_unavailable");
        })
        .map_err(|_| PreparedChildError::PostureMismatch)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .inspect_err(|_| {
                pressure_v3_stage("selected_child_runtime_executable_read_failed");
            })
            .map_err(|_| PreparedChildError::PostureMismatch)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let executable_identity = format!("sha256:{:x}", digest.finalize());
    if process_start_identity(pid).inspect_err(|_| {
        pressure_v3_stage("selected_child_runtime_final_start_identity_unavailable");
    })? != process_start_time_identity
    {
        pressure_v3_stage("selected_child_runtime_start_identity_changed");
        return Err(PreparedChildError::PostureMismatch);
    }
    pressure_running_child_identity_mismatch(
        child,
        process_start_time_identity.as_str(),
        executable_identity.as_str(),
        expected_session_object,
        observed_session_object,
        session_cloexec,
    );
    reconcile_running_child_identity(
        child,
        process_start_time_identity.as_str(),
        executable_identity.as_str(),
        expected_session_object,
        observed_session_object,
        session_cloexec,
    )
}

fn reconcile_running_child_identity(
    child: &LauncherChildProcessV1,
    process_start_time_identity: &str,
    executable_identity: &str,
    expected_session_object: DescriptorObject,
    observed_session_object: DescriptorObject,
    session_cloexec: bool,
) -> Result<(), PreparedChildError> {
    // Core must secure the inherited session against further execs before reporting posture.
    if process_start_time_identity != child.process_start_time_identity
        || executable_identity != child.ota_binary_identity
        || observed_session_object != expected_session_object
        || !session_cloexec
    {
        return Err(PreparedChildError::PostureMismatch);
    }
    Ok(())
}

fn pressure_running_child_identity_mismatch(
    child: &LauncherChildProcessV1,
    process_start_time_identity: &str,
    executable_identity: &str,
    expected_session_object: DescriptorObject,
    observed_session_object: DescriptorObject,
    session_cloexec: bool,
) {
    #[cfg(feature = "systemd-pressure-faults")]
    {
        if process_start_time_identity != child.process_start_time_identity {
            pressure_v3_stage("selected_child_runtime_start_identity_mismatch");
        } else if executable_identity != child.ota_binary_identity {
            pressure_v3_stage("selected_child_runtime_executable_identity_mismatch");
        } else if observed_session_object != expected_session_object {
            pressure_v3_stage("selected_child_runtime_session_object_mismatch");
        } else if !session_cloexec {
            pressure_v3_stage("selected_child_runtime_session_cloexec_mismatch");
        }
    }
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = (
        child,
        process_start_time_identity,
        executable_identity,
        expected_session_object,
        observed_session_object,
        session_cloexec,
    );
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
        systemd_launcher_profile_v4, systemd_protected_launcher_instance_v2_identity,
        systemd_protected_launcher_instance_v3_foundation_identity,
    };
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn test_descriptor_object() -> DescriptorObject {
        DescriptorObject {
            device: 1,
            inode: 2,
            file_type: libc::S_IFSOCK,
        }
    }

    #[test]
    fn running_child_identity_reconciliation_refuses_every_substitution() {
        let session = test_descriptor_object();
        let child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: identity('1'),
            invocation_id: String::from("invocation"),
            request_identity: identity('2'),
            pid: 41,
            process_start_time_identity: identity('3'),
            ota_binary_identity: identity('4'),
            principal_mapping_identity: identity('5'),
            working_directory_identity: identity('6'),
        };

        assert_eq!(
            reconcile_running_child_identity(
                &child,
                child.process_start_time_identity.as_str(),
                child.ota_binary_identity.as_str(),
                session,
                session,
                true,
            ),
            Ok(())
        );
        assert_eq!(
            reconcile_running_child_identity(
                &child,
                identity('7').as_str(),
                child.ota_binary_identity.as_str(),
                session,
                session,
                true,
            ),
            Err(PreparedChildError::PostureMismatch)
        );
        assert_eq!(
            reconcile_running_child_identity(
                &child,
                child.process_start_time_identity.as_str(),
                identity('8').as_str(),
                session,
                session,
                true,
            ),
            Err(PreparedChildError::PostureMismatch)
        );
        assert_eq!(
            reconcile_running_child_identity(
                &child,
                child.process_start_time_identity.as_str(),
                child.ota_binary_identity.as_str(),
                session,
                DescriptorObject {
                    inode: 3,
                    ..session
                },
                true,
            ),
            Err(PreparedChildError::PostureMismatch)
        );
        assert_eq!(
            reconcile_running_child_identity(
                &child,
                child.process_start_time_identity.as_str(),
                child.ota_binary_identity.as_str(),
                session,
                session,
                false,
            ),
            Err(PreparedChildError::PostureMismatch)
        );
    }

    #[cfg(feature = "systemd-pressure-faults")]
    #[test]
    fn snapshot_request_shape_marker_reports_complete_root_shape_without_values() {
        let fields = [
            "schema_version",
            "message_kind",
            "identity",
            "challenge",
            "nonce",
            "launcher_request_identity",
            "startup_continuation_identity",
            "session_identity",
            "contract_identity",
            "selected_execution_graph_identity",
        ];
        let mut complete = serde_json::Map::new();
        for field in fields {
            complete.insert(field.into(), serde_json::Value::Null);
        }

        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(complete.clone())),
            "authority_snapshot_request_nested_or_value_invalid"
        );

        let mut missing_challenge = complete.clone();
        missing_challenge.remove("challenge");
        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(missing_challenge)),
            "authority_snapshot_request_missing_only_challenge"
        );

        let mut missing_multiple = complete.clone();
        missing_multiple.remove("challenge");
        missing_multiple.remove("nonce");
        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(missing_multiple)),
            "authority_snapshot_request_multiple_required_fields_missing"
        );

        let mut unknown = complete.clone();
        unknown.insert("unexpected".into(), serde_json::Value::Null);
        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(unknown)),
            "authority_snapshot_request_unknown_field_complete_required_shape"
        );

        let mut unknown_missing_challenge = complete.clone();
        unknown_missing_challenge.remove("challenge");
        unknown_missing_challenge.insert("unexpected".into(), serde_json::Value::Null);
        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(
                unknown_missing_challenge
            )),
            "authority_snapshot_request_unknown_field_missing_only_challenge"
        );

        let mut unknown_missing_multiple = complete;
        unknown_missing_multiple.remove("challenge");
        unknown_missing_multiple.remove("nonce");
        unknown_missing_multiple.insert("unexpected".into(), serde_json::Value::Null);
        assert_eq!(
            authority_snapshot_request_shape_marker(&serde_json::Value::Object(
                unknown_missing_multiple
            )),
            "authority_snapshot_request_unknown_field_known_field_count_8"
        );

        let challenge_shape = serde_json::json!({
            "schema_version": null,
            "message_kind": null,
            "identity": null,
            "nonce_commitment": null,
            "issued_at_unix_seconds": null,
            "expires_at_unix_seconds": null,
        });
        assert_eq!(
            authority_snapshot_request_shape_marker(&challenge_shape),
            "authority_snapshot_request_matches_snapshot_challenge_root_shape"
        );

        let response_shape = serde_json::json!({
            "schema_version": null,
            "message_kind": null,
            "identity": null,
            "request_identity": null,
            "payload": null,
            "protected_snapshot_identity": null,
        });
        assert_eq!(
            authority_snapshot_request_shape_marker(&response_shape),
            "authority_snapshot_request_matches_snapshot_response_root_shape"
        );
    }

    #[test]
    fn secret_delivery_relay_state_refuses_interleaving_and_replay() {
        let awaiting = SecretDeliveryRelayState::AwaitPreludeOrLegacyOrCompletion;
        let prelude = advance_secret_delivery_relay_state(
            awaiting,
            Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST),
        )
        .expect("first same-child observation");
        assert_eq!(prelude, SecretDeliveryRelayState::PreludeResponded);
        assert!(matches!(
            advance_secret_delivery_relay_state(
                awaiting,
                Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                prelude,
                Some(PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                prelude,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        let snapshot = advance_secret_delivery_relay_state(
            prelude,
            Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST),
        )
        .expect("first snapshot");
        assert_eq!(snapshot, SecretDeliveryRelayState::SnapshotResponded);
        let snapshot_v2 = advance_secret_delivery_relay_state(
            prelude,
            Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST_V2),
        )
        .expect("V2 snapshot after same-child observation");
        assert_eq!(snapshot_v2, SecretDeliveryRelayState::SnapshotV2Responded);
        assert_eq!(
            advance_secret_delivery_relay_state(
                snapshot_v2,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4),
            )
            .expect("V4 binding after V2 snapshot"),
            SecretDeliveryRelayState::V4Bound
        );
        for (state, kind) in [
            (
                snapshot,
                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4,
            ),
            (
                snapshot_v2,
                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3,
            ),
            (snapshot_v2, PROTECTED_AUTHORITY_SNAPSHOT_REQUEST),
            (
                SecretDeliveryRelayState::V4Bound,
                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V4,
            ),
        ] {
            assert!(matches!(
                advance_secret_delivery_relay_state(state, Some(kind)),
                Err(PreparedChildError::AuthorizationAdmissionMismatch)
            ));
        }
        assert!(matches!(
            advance_secret_delivery_relay_state(
                snapshot,
                Some(PROTECTED_AUTHORITY_SNAPSHOT_REQUEST)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                snapshot,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert_eq!(
            advance_secret_delivery_relay_state(
                snapshot,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2)
            )
            .expect("snapshot-bound V2 binding"),
            SecretDeliveryRelayState::V2Bound
        );
        assert_eq!(
            advance_secret_delivery_relay_state(
                snapshot,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3),
            )
            .expect("same-child V3 binding request"),
            SecretDeliveryRelayState::V3Bound
        );
        assert!(matches!(
            advance_secret_delivery_relay_state(
                SecretDeliveryRelayState::PreludeResponded,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                SecretDeliveryRelayState::V3Bound,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                SecretDeliveryRelayState::V3Bound,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            advance_secret_delivery_relay_state(
                awaiting,
                Some(PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2)
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        assert!(matches!(
            parse_completion_for_state(
                serde_json::json!({
                    "message_kind": PROTECTED_AUTHORITY_SNAPSHOT_REQUEST
                }),
                SecretDeliveryRelayState::V2Bound,
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
        let mut early_refusal = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: "invocation".into(),
            lease_consumption_admission_identity: identity('1'),
            work_unit_identity: identity('2'),
            crossing_transaction_id: "crossing".into(),
            pending_crossing_transaction_identity: identity('3'),
            crossing_transaction_identity: identity('4'),
            receipt_archive_identity: None,
            outcome: ota_authority_protocol::LauncherExecutionOutcomeV1::Failed,
            exit_code: Some(1),
            receipt_status: "not_created".into(),
        };
        early_refusal.identity =
            launcher_execution_completion_v1_identity(&early_refusal).expect("refusal identity");
        assert_eq!(
            parse_pre_binding_refusal_completion(
                serde_json::to_value(&early_refusal).expect("refusal JSON"),
                SecretDeliveryRelayState::PreludeResponded,
            ),
            Ok(Some(early_refusal.clone()))
        );
        assert_eq!(
            parse_pre_binding_refusal_completion(
                serde_json::to_value(&early_refusal).expect("refusal JSON"),
                SecretDeliveryRelayState::SnapshotResponded,
            ),
            Ok(Some(early_refusal.clone()))
        );
        early_refusal.outcome = ota_authority_protocol::LauncherExecutionOutcomeV1::Completed;
        early_refusal.exit_code = Some(0);
        assert!(matches!(
            parse_pre_binding_refusal_completion(
                serde_json::to_value(&early_refusal).expect("completion JSON"),
                SecretDeliveryRelayState::PreludeResponded,
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        ));
    }

    #[cfg(feature = "protected-attestor")]
    #[derive(Clone, Copy)]
    enum EarlyRefusalPoint {
        AfterPrelude,
        AfterSnapshot,
    }

    #[cfg(feature = "protected-attestor")]
    #[derive(Clone, Copy)]
    enum EarlyCompletionCase {
        ValidFailed,
        ForgedIdentity,
        WrongInvocation,
        Completed,
        Interrupted,
    }

    #[cfg(feature = "protected-attestor")]
    struct EarlyRefusalRelayResult {
        result: Result<(LauncherExecutionCompletionV1, Option<i32>), PreparedChildError>,
        persisted: Vec<LauncherExecutionCompletionV1>,
        snapshot_calls: usize,
        v2_binding_calls: usize,
    }

    #[cfg(feature = "protected-attestor")]
    fn exercise_early_refusal_relay(
        consumption: &LeaseConsumptionRelayEvidenceV1,
        record: &LauncherChildProcessV1,
        point: EarlyRefusalPoint,
        case: EarlyCompletionCase,
    ) -> EarlyRefusalRelayResult {
        let (
            observation_request,
            observation_response,
            prelude,
            snapshot_request,
            snapshot_response,
            _,
            _,
        ) = crate::protected_authority_snapshot::tests::relay_protocol_fixture();
        let mut completion = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: record.invocation_id.clone(),
            lease_consumption_admission_identity: consumption.admission.identity.clone(),
            work_unit_identity: consumption.admission.work_unit_identity.clone(),
            crossing_transaction_id: consumption.admission.crossing_transaction_id.clone(),
            pending_crossing_transaction_identity: consumption
                .admission
                .crossing_transaction_identity
                .clone(),
            crossing_transaction_identity: identity('f'),
            receipt_archive_identity: None,
            outcome: ota_authority_protocol::LauncherExecutionOutcomeV1::Failed,
            exit_code: Some(1),
            receipt_status: String::from("not_created"),
        };
        match case {
            EarlyCompletionCase::ValidFailed | EarlyCompletionCase::ForgedIdentity => {}
            EarlyCompletionCase::WrongInvocation => {
                completion.invocation_id = String::from("other-invocation");
            }
            EarlyCompletionCase::Completed => {
                completion.outcome = ota_authority_protocol::LauncherExecutionOutcomeV1::Completed;
                completion.exit_code = Some(0);
            }
            EarlyCompletionCase::Interrupted => {
                completion.outcome =
                    ota_authority_protocol::LauncherExecutionOutcomeV1::Interrupted;
                completion.exit_code = Some(130);
            }
        }
        completion.identity =
            launcher_execution_completion_v1_identity(&completion).expect("completion identity");
        if matches!(case, EarlyCompletionCase::ForgedIdentity) {
            completion.identity = identity('0');
        }

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork early-refusal child");
        if pid == 0 {
            unsafe { libc::_exit(1) };
        }
        let (launcher_session, mut core) =
            UnixStream::pair().expect("early-refusal completion session");
        let (stdout, stdout_writer) = pipe_cloexec().expect("early-refusal stdout");
        let (stderr, stderr_writer) = pipe_cloexec().expect("early-refusal stderr");
        drop(stdout_writer);
        drop(stderr_writer);
        let (client, _pressure_client) = UnixStream::pair().expect("early-refusal output session");
        let expect_persistence = matches!(case, EarlyCompletionCase::ValidFailed);
        let sent_completion = completion.clone();
        let expected_observation_response = observation_response.clone();
        let expected_prelude = prelude.clone();
        let expected_snapshot_response = snapshot_response.clone();
        let core_thread = thread::spawn(move || {
            write_json_frame_blocking(&mut core, &observation_request)
                .expect("write observation request");
            let observed_response: ProtectedLauncherCapabilityObservationResponseV1 =
                read_json_frame_blocking(&mut core).expect("read observation response");
            let observed_prelude: ProtectedSameChildCapabilityPreludeV1 =
                read_json_frame_blocking(&mut core).expect("read private prelude");
            assert_eq!(observed_response, expected_observation_response);
            assert_eq!(observed_prelude, expected_prelude);
            if matches!(point, EarlyRefusalPoint::AfterSnapshot) {
                write_json_frame_blocking(&mut core, &snapshot_request)
                    .expect("write snapshot request");
                let observed_snapshot: ProtectedAuthoritySnapshotResponseV1 =
                    read_json_frame_blocking(&mut core).expect("read snapshot response");
                assert_eq!(observed_snapshot, expected_snapshot_response);
            }
            write_json_frame_blocking(&mut core, &sent_completion).expect("write early completion");
            if expect_persistence {
                let persistence: LauncherExecutionCompletionPersistenceV1 =
                    read_json_frame_blocking(&mut core).expect("read completion persistence");
                assert_eq!(persistence.completion_identity, sent_completion.identity);
            }
        });
        let mut child = PreparedChild {
            pid,
            record: LauncherChildProcessV1 {
                pid: pid as u32,
                ..record.clone()
            },
            launcher_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        let mut persisted = Vec::new();
        let mut snapshot_calls = 0;
        let mut v2_binding_calls = 0;
        let result = child.relay_selected_execution_with_secret_binding(
            &client,
            consumption,
            |request, _| {
                assert_eq!(request.identity, prelude.observation_request_identity);
                Ok((observation_response, prelude))
            },
            |request, _| {
                snapshot_calls += 1;
                assert_eq!(request.identity, snapshot_response.request_identity);
                Ok(snapshot_response)
            },
            |_, _| unreachable!("early refusal must not request V2 snapshot"),
            |_, _| unreachable!("same-child lane must not use legacy binding"),
            |_, _| {
                v2_binding_calls += 1;
                unreachable!("early refusal must not request V2 binding")
            },
            |_, _| unreachable!("early refusal must not request V3 binding"),
            |_, _| unreachable!("early refusal must not request V4 binding"),
            |completion| {
                persisted.push(completion);
                Ok(())
            },
        );
        if child.pid > 0 {
            child
                .terminate_and_reap()
                .expect("clean rejected early-refusal child");
        }
        core_thread.join().expect("early-refusal core thread");
        EarlyRefusalRelayResult {
            result,
            persisted,
            snapshot_calls,
            v2_binding_calls,
        }
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
        let launcher_profile = systemd_launcher_profile_v4();
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
            selected_session_object: test_descriptor_object(),
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
            selected_session_object: test_descriptor_object(),
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
            selected_session_object: test_descriptor_object(),
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
            selected_session_object: test_descriptor_object(),
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
            selected_session_object: test_descriptor_object(),
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
            selected_session_object: test_descriptor_object(),
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
        let binding_request: ProtectedLauncherSecretDeliveryTransactionBindingRequestV1 =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "message_kind": PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST,
                "identity": identity('1'),
                "launcher_request_identity": identity('2'),
                "observation": {
                    "schema_version": 1,
                    "message_kind": "protected_launcher_capability_observation_request",
                    "identity": identity('3'),
                    "challenge": {
                        "schema_version": 1,
                        "message_kind": "protected_launcher_capability_observation_challenge",
                        "identity": identity('4'),
                        "workflow_run_id": "1",
                        "workflow_run_attempt": "1",
                        "workflow_reference": "ota-run/ota/.github/workflows/test.yml@refs/heads/main",
                        "nonce_commitment": identity('5'),
                        "issued_at_unix_seconds": 1,
                        "expires_at_unix_seconds": 2
                    },
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "runner_version": "2.337.0",
                    "expected_launcher_request_identity": identity('2')
                },
                "secret_transaction_candidate_identity": identity('6'),
                "startup_continuation_identity": identity('7'),
                "session_identity": identity('8')
            }))
            .expect("binding request fixture");
        let binding_response: ProtectedLauncherSecretDeliveryTransactionBindingResponseV1 =
            serde_json::from_value(serde_json::json!({
                "schema_version": 1,
                "message_kind": "protected_launcher_secret_delivery_transaction_binding_response",
                "request_identity": identity('1'),
                "binding": {
                    "schema_version": 1,
                    "message_kind": "protected_launcher_secret_delivery_transaction_binding",
                    "identity": identity('9'),
                    "request_identity": identity('1'),
                    "launcher_request_identity": identity('2'),
                    "startup_continuation_identity": identity('7'),
                    "session_identity": identity('8'),
                    "protected_capability_identity": identity('a'),
                    "secret_transaction_candidate_identity": identity('6'),
                    "observation_request_identity": identity('3'),
                    "projection_identity": identity('b'),
                    "verifier_identity": identity('c'),
                    "installation_evidence_identity": identity('d'),
                    "expires_at_unix_seconds": 2
                },
                "projection": {
                    "payload": {
                        "schema_version": 1,
                        "evidence_kind": "protected_launcher_capability_observation",
                        "challenge_identity": identity('4'),
                        "derivation": "verified",
                        "target": {
                            "environment": "self_hosted",
                            "os": "linux",
                            "architecture": "x64"
                        },
                        "capability_class": "systemd_protected_launcher_v4",
                        "runner_version": "2.337.0",
                        "signing_key_identity": identity('e')
                    },
                    "projection_identity": identity('b'),
                    "signature": "A".repeat(86)
                }
            }))
            .expect("binding response fixture");
        let expected_binding_request = binding_request.clone();
        let expected_binding_response = binding_response.clone();
        let duplicate_binding_request = binding_request.clone();
        let duplicate_binding_response = binding_response.clone();
        let core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut core, &binding_request).expect("send binding request");
            let response: ProtectedLauncherSecretDeliveryTransactionBindingResponseV1 =
                read_json_frame_blocking(&mut core).expect("binding response");
            assert_eq!(response, binding_response);
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
            selected_session_object: test_descriptor_object(),
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        let mut persisted = Vec::new();
        let mut binding_calls = 0;
        let (observed_completion, observed_exit) = child
            .relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("legacy V1 binding must not request a prelude"),
                |_, _| unreachable!("legacy V1 binding must not request a snapshot"),
                |_, _| unreachable!("legacy V1 binding must not request a V2 snapshot"),
                |request, _session| {
                    binding_calls += 1;
                    assert_eq!(request, &expected_binding_request);
                    Ok(expected_binding_response)
                },
                |_, _| unreachable!("legacy V1 binding must not request V2 binding"),
                |_, _| unreachable!("legacy V1 binding must not request V3 binding"),
                |_, _| unreachable!("legacy V1 binding must not request V4 binding"),
                |completion| {
                    persisted.push(completion);
                    Ok(())
                },
            )
            .expect("selected execution relay");
        assert_eq!(observed_completion, expected_completion);
        assert_eq!(observed_exit, Some(0));
        assert_eq!(persisted, vec![expected_completion.clone()]);
        assert_eq!(binding_calls, 1);
        core_thread.join().expect("completion core thread");
        let first: LauncherOutputFrameV1 =
            read_json_frame_blocking(&mut pressure_client).expect("first output");
        let second: LauncherOutputFrameV1 =
            read_json_frame_blocking(&mut pressure_client).expect("second output");
        assert_eq!((first.sequence, second.sequence), (0, 1));
        assert_ne!(first.stream, second.stream);

        let direct_pid = unsafe { libc::fork() };
        assert!(direct_pid >= 0, "fork direct-completion child");
        if direct_pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let (direct_session, mut direct_core) =
            UnixStream::pair().expect("direct completion session");
        let (direct_stdout, direct_stdout_writer) = pipe_cloexec().expect("direct stdout pipe");
        let (direct_stderr, direct_stderr_writer) = pipe_cloexec().expect("direct stderr pipe");
        drop(direct_stdout_writer);
        drop(direct_stderr_writer);
        let direct_completion = expected_completion.clone();
        let direct_core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut direct_core, &direct_completion)
                .expect("send direct completion");
            let persistence: LauncherExecutionCompletionPersistenceV1 =
                read_json_frame_blocking(&mut direct_core).expect("direct completion persistence");
            assert_eq!(persistence.completion_identity, direct_completion.identity);
        });
        let mut direct_child = PreparedChild {
            pid: direct_pid,
            record: LauncherChildProcessV1 {
                pid: direct_pid as u32,
                ..child.record.clone()
            },
            launcher_session: direct_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(direct_stdout),
            stderr: Some(direct_stderr),
        };
        let (direct_observed, direct_exit) = direct_child
            .relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("ordinary completion must not request a prelude"),
                |_, _| unreachable!("ordinary completion must not request a snapshot"),
                |_, _| unreachable!("ordinary completion must not request a V2 snapshot"),
                |_, _| unreachable!("ordinary completion must not request secret binding"),
                |_, _| unreachable!("ordinary completion must not request V2 secret binding"),
                |_, _| unreachable!("ordinary completion must not request V3 secret binding"),
                |_, _| unreachable!("ordinary completion must not request V4 secret binding"),
                |_| Ok(()),
            )
            .expect("ordinary selected execution relay");
        assert_eq!(direct_observed, expected_completion);
        assert_eq!(direct_exit, Some(0));
        direct_core_thread
            .join()
            .expect("direct completion core thread");

        let duplicate_pid = unsafe { libc::fork() };
        assert!(duplicate_pid >= 0, "fork duplicate-binding child");
        if duplicate_pid == 0 {
            unsafe { libc::pause() };
            unsafe { libc::_exit(0) };
        }
        let (duplicate_session, mut duplicate_core) =
            UnixStream::pair().expect("duplicate binding session");
        let (duplicate_stdout, duplicate_stdout_writer) =
            pipe_cloexec().expect("duplicate stdout pipe");
        let (duplicate_stderr, duplicate_stderr_writer) =
            pipe_cloexec().expect("duplicate stderr pipe");
        drop(duplicate_stdout_writer);
        drop(duplicate_stderr_writer);
        let sent_duplicate_request = duplicate_binding_request.clone();
        let duplicate_core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut duplicate_core, &sent_duplicate_request)
                .expect("send first binding request");
            let _: ProtectedLauncherSecretDeliveryTransactionBindingResponseV1 =
                read_json_frame_blocking(&mut duplicate_core).expect("first binding response");
            write_json_frame_blocking(&mut duplicate_core, &sent_duplicate_request)
                .expect("send duplicate binding request");
        });
        let mut duplicate_child = PreparedChild {
            pid: duplicate_pid,
            record: LauncherChildProcessV1 {
                pid: duplicate_pid as u32,
                ..child.record.clone()
            },
            launcher_session: duplicate_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(duplicate_stdout),
            stderr: Some(duplicate_stderr),
        };
        assert_eq!(
            duplicate_child.relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("legacy V1 binding must not request a prelude"),
                |_, _| unreachable!("legacy V1 binding must not request a snapshot"),
                |_, _| unreachable!("legacy V1 binding must not request a V2 snapshot"),
                |request, _| {
                    assert_eq!(request, &duplicate_binding_request);
                    Ok(duplicate_binding_response)
                },
                |_, _| unreachable!("legacy V1 binding must not request V2 binding"),
                |_, _| unreachable!("legacy V1 binding must not request V3 binding"),
                |_, _| unreachable!("legacy V1 binding must not request V4 binding"),
                |_| unreachable!("duplicate binding must not reach completion persistence"),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        );
        duplicate_child
            .terminate_and_reap()
            .expect("clean duplicate-binding child");
        duplicate_core_thread
            .join()
            .expect("duplicate binding core thread");

        let malformed_pid = unsafe { libc::fork() };
        assert!(malformed_pid >= 0, "fork malformed-binding child");
        if malformed_pid == 0 {
            unsafe { libc::pause() };
            unsafe { libc::_exit(0) };
        }
        let (malformed_session, mut malformed_core) =
            UnixStream::pair().expect("malformed binding session");
        let (malformed_stdout, malformed_stdout_writer) =
            pipe_cloexec().expect("malformed stdout pipe");
        let (malformed_stderr, malformed_stderr_writer) =
            pipe_cloexec().expect("malformed stderr pipe");
        drop(malformed_stdout_writer);
        drop(malformed_stderr_writer);
        let malformed_core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(
                &mut malformed_core,
                &serde_json::json!({
                    "message_kind": PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST
                }),
            )
            .expect("send malformed binding request");
        });
        let mut malformed_child = PreparedChild {
            pid: malformed_pid,
            record: LauncherChildProcessV1 {
                pid: malformed_pid as u32,
                ..child.record.clone()
            },
            launcher_session: malformed_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(malformed_stdout),
            stderr: Some(malformed_stderr),
        };
        assert_eq!(
            malformed_child.relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("malformed V1 binding must not request a prelude"),
                |_, _| unreachable!("malformed V1 binding must not request a snapshot"),
                |_, _| unreachable!("malformed V1 binding must not request a V2 snapshot"),
                |_, _| unreachable!("malformed binding must refuse before callback"),
                |_, _| unreachable!("malformed V1 binding must not request V2 binding"),
                |_, _| unreachable!("malformed V1 binding must not request V3 binding"),
                |_, _| unreachable!("malformed V1 binding must not request V4 binding"),
                |_| unreachable!("malformed binding must not reach completion persistence"),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        );
        malformed_child
            .terminate_and_reap()
            .expect("clean malformed-binding child");
        malformed_core_thread
            .join()
            .expect("malformed binding core thread");

        #[cfg(feature = "protected-attestor")]
        {
            let (
                observation_request,
                observation_response,
                prelude,
                snapshot_request,
                snapshot_response,
                v2_request,
                v2_response,
            ) = crate::protected_authority_snapshot::tests::relay_protocol_fixture();
            let sequence_pid = unsafe { libc::fork() };
            assert!(sequence_pid >= 0, "fork same-child sequence child");
            if sequence_pid == 0 {
                unsafe { libc::_exit(0) };
            }
            let (sequence_session, mut sequence_core) =
                UnixStream::pair().expect("same-child sequence session");
            let (sequence_stdout, sequence_stdout_writer) =
                pipe_cloexec().expect("same-child sequence stdout");
            let (sequence_stderr, sequence_stderr_writer) =
                pipe_cloexec().expect("same-child sequence stderr");
            drop(sequence_stdout_writer);
            drop(sequence_stderr_writer);
            let expected_observation_response = observation_response.clone();
            let expected_prelude = prelude.clone();
            let expected_snapshot_response = snapshot_response.clone();
            let expected_v2_response = v2_response.clone();
            let sequence_completion = expected_completion.clone();
            let sequence_core_thread = thread::spawn(move || {
                write_json_frame_blocking(&mut sequence_core, &observation_request)
                    .expect("write observation request");
                let observed_response: ProtectedLauncherCapabilityObservationResponseV1 =
                    read_json_frame_blocking(&mut sequence_core)
                        .expect("read observation response");
                let observed_prelude: ProtectedSameChildCapabilityPreludeV1 =
                    read_json_frame_blocking(&mut sequence_core).expect("read private prelude");
                assert_eq!(observed_response, expected_observation_response);
                assert_eq!(observed_prelude, expected_prelude);
                write_json_frame_blocking(&mut sequence_core, &snapshot_request)
                    .expect("write snapshot request");
                let observed_snapshot: ProtectedAuthoritySnapshotResponseV1 =
                    read_json_frame_blocking(&mut sequence_core).expect("read snapshot response");
                assert_eq!(observed_snapshot, expected_snapshot_response);
                write_json_frame_blocking(&mut sequence_core, &v2_request)
                    .expect("write V2 binding request");
                let observed_v2: ProtectedLauncherSecretDeliveryTransactionBindingResponseV2 =
                    read_json_frame_blocking(&mut sequence_core).expect("read V2 binding response");
                assert_eq!(observed_v2, expected_v2_response);
                write_json_frame_blocking(&mut sequence_core, &sequence_completion)
                    .expect("write sequence completion");
                let persistence: LauncherExecutionCompletionPersistenceV1 =
                    read_json_frame_blocking(&mut sequence_core)
                        .expect("read sequence completion persistence");
                assert_eq!(
                    persistence.completion_identity,
                    sequence_completion.identity
                );
            });
            let mut sequence_child = PreparedChild {
                pid: sequence_pid,
                record: LauncherChildProcessV1 {
                    pid: sequence_pid as u32,
                    ..child.record.clone()
                },
                launcher_session: sequence_session,
                selected_session_object: test_descriptor_object(),
                stdout: Some(sequence_stdout),
                stderr: Some(sequence_stderr),
            };
            let (sequence_observed, sequence_exit) = sequence_child
                .relay_selected_execution_with_secret_binding(
                    &client,
                    &consumption,
                    |request, _| {
                        assert_eq!(request.identity, prelude.observation_request_identity);
                        Ok((observation_response, prelude))
                    },
                    |request, _| {
                        assert_eq!(request.identity, snapshot_response.request_identity);
                        Ok(snapshot_response)
                    },
                    |_, _| unreachable!("same-child V2 lane must not use V2 snapshot"),
                    |_, _| unreachable!("same-child V2 lane must not use legacy binding"),
                    |request, _| {
                        assert_eq!(request.identity, v2_response.request_identity);
                        Ok(v2_response)
                    },
                    |_, _| unreachable!("same-child V2 lane must not use V3 binding"),
                    |_, _| unreachable!("same-child V2 lane must not use V4 binding"),
                    |_| Ok(()),
                )
                .expect("same-child framed relay");
            assert_eq!(sequence_observed, expected_completion);
            assert_eq!(sequence_exit, Some(0));
            sequence_core_thread
                .join()
                .expect("same-child sequence core thread");

            let (
                observation_request,
                observation_response,
                prelude,
                snapshot_request,
                snapshot_response,
                v3_request,
                v3_response,
            ) = crate::protected_authority_snapshot::tests::relay_protocol_fixture_v3();
            let sequence_v3_pid = unsafe { libc::fork() };
            assert!(sequence_v3_pid >= 0, "fork same-child V3 sequence child");
            if sequence_v3_pid == 0 {
                unsafe { libc::_exit(0) };
            }
            let (sequence_v3_session, mut sequence_v3_core) =
                UnixStream::pair().expect("same-child V3 sequence session");
            let (sequence_v3_stdout, sequence_v3_stdout_writer) =
                pipe_cloexec().expect("same-child V3 sequence stdout");
            let (sequence_v3_stderr, sequence_v3_stderr_writer) =
                pipe_cloexec().expect("same-child V3 sequence stderr");
            drop(sequence_v3_stdout_writer);
            drop(sequence_v3_stderr_writer);
            let expected_observation_response = observation_response.clone();
            let expected_prelude = prelude.clone();
            let expected_snapshot_response = snapshot_response.clone();
            let expected_v3_response = v3_response.clone();
            let sequence_v3_completion = expected_completion.clone();
            let sequence_v3_core_thread = thread::spawn(move || {
                write_json_frame_blocking(&mut sequence_v3_core, &observation_request)
                    .expect("write V3 observation request");
                let observed_response: ProtectedLauncherCapabilityObservationResponseV1 =
                    read_json_frame_blocking(&mut sequence_v3_core)
                        .expect("read V3 observation response");
                let observed_prelude: ProtectedSameChildCapabilityPreludeV1 =
                    read_json_frame_blocking(&mut sequence_v3_core)
                        .expect("read V3 private prelude");
                assert_eq!(observed_response, expected_observation_response);
                assert_eq!(observed_prelude, expected_prelude);
                write_json_frame_blocking(&mut sequence_v3_core, &snapshot_request)
                    .expect("write V3 snapshot request");
                let observed_snapshot: ProtectedAuthoritySnapshotResponseV1 =
                    read_json_frame_blocking(&mut sequence_v3_core)
                        .expect("read V3 snapshot response");
                assert_eq!(observed_snapshot, expected_snapshot_response);
                write_json_frame_blocking(&mut sequence_v3_core, &v3_request)
                    .expect("write V3 binding request");
                let observed_v3: ProtectedLauncherSecretDeliveryTransactionBindingResponseV3 =
                    read_json_frame_blocking(&mut sequence_v3_core)
                        .expect("read V3 binding response");
                assert_eq!(observed_v3, expected_v3_response);
                write_json_frame_blocking(&mut sequence_v3_core, &sequence_v3_completion)
                    .expect("write V3 sequence completion");
                let persistence: LauncherExecutionCompletionPersistenceV1 =
                    read_json_frame_blocking(&mut sequence_v3_core)
                        .expect("read V3 sequence completion persistence");
                assert_eq!(
                    persistence.completion_identity,
                    sequence_v3_completion.identity
                );
            });
            let mut sequence_v3_child = PreparedChild {
                pid: sequence_v3_pid,
                record: LauncherChildProcessV1 {
                    pid: sequence_v3_pid as u32,
                    ..child.record.clone()
                },
                launcher_session: sequence_v3_session,
                selected_session_object: test_descriptor_object(),
                stdout: Some(sequence_v3_stdout),
                stderr: Some(sequence_v3_stderr),
            };
            let (sequence_v3_observed, sequence_v3_exit) = sequence_v3_child
                .relay_selected_execution_with_secret_binding(
                    &client,
                    &consumption,
                    |request, _| {
                        assert_eq!(request.identity, prelude.observation_request_identity);
                        Ok((observation_response, prelude))
                    },
                    |request, _| {
                        assert_eq!(request.identity, snapshot_response.request_identity);
                        Ok(snapshot_response)
                    },
                    |_, _| unreachable!("same-child V3 lane must not use V2 snapshot"),
                    |_, _| unreachable!("same-child V3 lane must not use legacy binding"),
                    |_, _| unreachable!("same-child V3 lane must not use V2 binding"),
                    |request, _| {
                        assert_eq!(request.identity, v3_response.request_identity);
                        Ok(v3_response)
                    },
                    |_, _| unreachable!("same-child V3 lane must not use V4 binding"),
                    |_| Ok(()),
                )
                .expect("same-child framed V3 relay");
            assert_eq!(sequence_v3_observed, expected_completion);
            assert_eq!(sequence_v3_exit, Some(0));
            sequence_v3_core_thread
                .join()
                .expect("same-child V3 sequence core thread");

            let (
                observation_request,
                observation_response,
                prelude,
                snapshot_request,
                snapshot_response,
                v4_request,
                v4_response,
            ) = crate::protected_authority_snapshot::tests::relay_protocol_fixture_v4();
            let sequence_v4_pid = unsafe { libc::fork() };
            assert!(sequence_v4_pid >= 0, "fork same-child V4 sequence child");
            if sequence_v4_pid == 0 {
                unsafe { libc::_exit(0) };
            }
            let (sequence_v4_session, mut sequence_v4_core) =
                UnixStream::pair().expect("same-child V4 sequence session");
            let (sequence_v4_stdout, sequence_v4_stdout_writer) =
                pipe_cloexec().expect("same-child V4 sequence stdout");
            let (sequence_v4_stderr, sequence_v4_stderr_writer) =
                pipe_cloexec().expect("same-child V4 sequence stderr");
            drop(sequence_v4_stdout_writer);
            drop(sequence_v4_stderr_writer);
            let expected_observation_response = observation_response.clone();
            let expected_prelude = prelude.clone();
            let expected_snapshot_response = snapshot_response.clone();
            let expected_v4_response = v4_response.clone();
            let sequence_v4_completion = expected_completion.clone();
            let sequence_v4_core_thread = thread::spawn(move || {
                write_json_frame_blocking(&mut sequence_v4_core, &observation_request)
                    .expect("write V4 observation request");
                let observed_response: ProtectedLauncherCapabilityObservationResponseV1 =
                    read_json_frame_blocking(&mut sequence_v4_core)
                        .expect("read V4 observation response");
                let observed_prelude: ProtectedSameChildCapabilityPreludeV1 =
                    read_json_frame_blocking(&mut sequence_v4_core)
                        .expect("read V4 private prelude");
                assert_eq!(observed_response, expected_observation_response);
                assert_eq!(observed_prelude, expected_prelude);
                write_json_frame_blocking(&mut sequence_v4_core, &snapshot_request)
                    .expect("write V4 snapshot request");
                let observed_snapshot: ProtectedAuthoritySnapshotResponseV2 =
                    read_json_frame_blocking(&mut sequence_v4_core)
                        .expect("read V4 snapshot response");
                assert_eq!(observed_snapshot, expected_snapshot_response);
                write_json_frame_blocking(&mut sequence_v4_core, &v4_request)
                    .expect("write V4 binding request");
                let observed_v4: ProtectedLauncherSecretDeliveryTransactionBindingResponseV4 =
                    read_json_frame_blocking(&mut sequence_v4_core)
                        .expect("read V4 binding response");
                assert_eq!(observed_v4, expected_v4_response);
                write_json_frame_blocking(&mut sequence_v4_core, &sequence_v4_completion)
                    .expect("write V4 sequence completion");
                let persistence: LauncherExecutionCompletionPersistenceV1 =
                    read_json_frame_blocking(&mut sequence_v4_core)
                        .expect("read V4 sequence completion persistence");
                assert_eq!(
                    persistence.completion_identity,
                    sequence_v4_completion.identity
                );
            });
            let mut sequence_v4_child = PreparedChild {
                pid: sequence_v4_pid,
                record: LauncherChildProcessV1 {
                    pid: sequence_v4_pid as u32,
                    ..child.record.clone()
                },
                launcher_session: sequence_v4_session,
                selected_session_object: test_descriptor_object(),
                stdout: Some(sequence_v4_stdout),
                stderr: Some(sequence_v4_stderr),
            };
            let (sequence_v4_observed, sequence_v4_exit) = sequence_v4_child
                .relay_selected_execution_with_secret_binding(
                    &client,
                    &consumption,
                    |request, _| {
                        assert_eq!(request.identity, prelude.observation_request_identity);
                        Ok((observation_response, prelude))
                    },
                    |_, _| unreachable!("same-child V4 lane must not use V1 snapshot"),
                    |request, _| {
                        assert_eq!(request.identity, snapshot_response.request_identity);
                        Ok(snapshot_response)
                    },
                    |_, _| unreachable!("same-child V4 lane must not use legacy binding"),
                    |_, _| unreachable!("same-child V4 lane must not use V2 binding"),
                    |_, _| unreachable!("same-child V4 lane must not use V3 binding"),
                    |request, _| {
                        assert_eq!(request.identity, v4_response.request_identity);
                        Ok(v4_response)
                    },
                    |_| Ok(()),
                )
                .expect("same-child framed V4 relay");
            assert_eq!(sequence_v4_observed, expected_completion);
            assert_eq!(sequence_v4_exit, Some(0));
            sequence_v4_core_thread
                .join()
                .expect("same-child V4 sequence core thread");

            for point in [
                EarlyRefusalPoint::AfterPrelude,
                EarlyRefusalPoint::AfterSnapshot,
            ] {
                let valid = exercise_early_refusal_relay(
                    &consumption,
                    &child.record,
                    point,
                    EarlyCompletionCase::ValidFailed,
                );
                let (completion, observed_exit) = valid.result.expect("valid early refusal");
                assert_eq!(
                    completion.outcome,
                    ota_authority_protocol::LauncherExecutionOutcomeV1::Failed
                );
                assert_eq!(observed_exit, Some(1));
                assert_eq!(valid.persisted, vec![completion]);
                assert_eq!(
                    valid.snapshot_calls,
                    usize::from(matches!(point, EarlyRefusalPoint::AfterSnapshot))
                );
                assert_eq!(valid.v2_binding_calls, 0);

                for case in [
                    EarlyCompletionCase::ForgedIdentity,
                    EarlyCompletionCase::WrongInvocation,
                    EarlyCompletionCase::Completed,
                    EarlyCompletionCase::Interrupted,
                ] {
                    let rejected =
                        exercise_early_refusal_relay(&consumption, &child.record, point, case);
                    assert!(matches!(
                        rejected.result,
                        Err(PreparedChildError::ExecutionCompletionIdentityMismatch)
                            | Err(PreparedChildError::AuthorizationAdmissionMismatch)
                    ));
                    assert!(rejected.persisted.is_empty());
                    assert_eq!(
                        rejected.snapshot_calls,
                        usize::from(matches!(point, EarlyRefusalPoint::AfterSnapshot))
                    );
                    assert_eq!(rejected.v2_binding_calls, 0);
                }
            }
        }

        let direct_v2_pid = unsafe { libc::fork() };
        assert!(direct_v2_pid >= 0, "fork direct-v2-binding child");
        if direct_v2_pid == 0 {
            unsafe { libc::pause() };
            unsafe { libc::_exit(0) };
        }
        let (direct_v2_session, mut direct_v2_core) =
            UnixStream::pair().expect("direct V2 binding session");
        let (direct_v2_stdout, direct_v2_stdout_writer) =
            pipe_cloexec().expect("direct V2 stdout pipe");
        let (direct_v2_stderr, direct_v2_stderr_writer) =
            pipe_cloexec().expect("direct V2 stderr pipe");
        drop(direct_v2_stdout_writer);
        drop(direct_v2_stderr_writer);
        let direct_v2_request = {
            let mut value = serde_json::to_value(&expected_binding_request)
                .expect("serialize V1 binding request");
            value["schema_version"] = serde_json::json!(2);
            value["message_kind"] = serde_json::json!(
                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V2
            );
            value["protected_snapshot_identity"] = serde_json::json!(identity('f'));
            value
        };
        let direct_v2_core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut direct_v2_core, &direct_v2_request)
                .expect("send direct V2 binding request");
        });
        let mut direct_v2_child = PreparedChild {
            pid: direct_v2_pid,
            record: LauncherChildProcessV1 {
                pid: direct_v2_pid as u32,
                ..child.record.clone()
            },
            launcher_session: direct_v2_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(direct_v2_stdout),
            stderr: Some(direct_v2_stderr),
        };
        assert_eq!(
            direct_v2_child.relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("direct V2 binding must not request a prelude"),
                |_, _| unreachable!("direct V2 binding must not request a snapshot"),
                |_, _| unreachable!("direct V2 binding must not request a V2 snapshot"),
                |_, _| unreachable!("direct V2 binding must not request V1 binding"),
                |_, _| unreachable!("direct V2 binding must refuse before its callback"),
                |_, _| unreachable!("direct V2 binding must refuse before a V3 callback"),
                |_, _| unreachable!("direct V2 binding must refuse before a V4 callback"),
                |_| unreachable!("direct V2 binding must not reach completion persistence"),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        );
        direct_v2_child
            .terminate_and_reap()
            .expect("clean direct V2 binding child");
        direct_v2_core_thread
            .join()
            .expect("direct V2 binding core thread");

        let direct_v3_pid = unsafe { libc::fork() };
        assert!(direct_v3_pid >= 0, "fork direct-V3-binding child");
        if direct_v3_pid == 0 {
            unsafe { libc::pause() };
            unsafe { libc::_exit(0) };
        }
        let (direct_v3_session, mut direct_v3_core) =
            UnixStream::pair().expect("direct V3 binding session");
        let (direct_v3_stdout, direct_v3_stdout_writer) =
            pipe_cloexec().expect("direct V3 stdout pipe");
        let (direct_v3_stderr, direct_v3_stderr_writer) =
            pipe_cloexec().expect("direct V3 stderr pipe");
        drop(direct_v3_stdout_writer);
        drop(direct_v3_stderr_writer);
        let direct_v3_request = {
            let mut value = serde_json::to_value(&expected_binding_request)
                .expect("serialize V1 binding request");
            value["schema_version"] = serde_json::json!(3);
            value["message_kind"] = serde_json::json!(
                PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST_V3
            );
            value["protected_snapshot_identity"] = serde_json::json!(identity('f'));
            value["transport_dependency_record_identity"] = serde_json::json!(identity('g'));
            value
        };
        let direct_v3_core_thread = std::thread::spawn(move || {
            write_json_frame_blocking(&mut direct_v3_core, &direct_v3_request)
                .expect("send direct V3 binding request");
        });
        let mut direct_v3_child = PreparedChild {
            pid: direct_v3_pid,
            record: LauncherChildProcessV1 {
                pid: direct_v3_pid as u32,
                ..child.record.clone()
            },
            launcher_session: direct_v3_session,
            selected_session_object: test_descriptor_object(),
            stdout: Some(direct_v3_stdout),
            stderr: Some(direct_v3_stderr),
        };
        assert_eq!(
            direct_v3_child.relay_selected_execution_with_secret_binding(
                &client,
                &consumption,
                |_, _| unreachable!("direct V3 binding must not request a prelude"),
                |_, _| unreachable!("direct V3 binding must not request a snapshot"),
                |_, _| unreachable!("direct V3 binding must not request a V2 snapshot"),
                |_, _| unreachable!("direct V3 binding must not request V1 binding"),
                |_, _| unreachable!("direct V3 binding must not request V2 binding"),
                |_, _| unreachable!("direct V3 binding must refuse before its callback"),
                |_, _| unreachable!("direct V3 binding must refuse before a V4 callback"),
                |_| unreachable!("direct V3 binding must not reach completion persistence"),
            ),
            Err(PreparedChildError::AuthorizationAdmissionMismatch)
        );
        direct_v3_child
            .terminate_and_reap()
            .expect("clean direct V3 binding child");
        direct_v3_core_thread
            .join()
            .expect("direct V3 binding core thread");
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
            selected_session_object: test_descriptor_object(),
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
        let boot_file = File::open("/proc/sys/kernel/random/boot_id")
            .expect("manager-opened boot descriptor fixture");
        let boot_object = descriptor_object(boot_file.as_raw_fd()).expect("boot descriptor object");
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
        assert!(
            std::fs::read_dir(format!("/proc/{}/fd", child.record.pid))
                .expect("stopped child descriptor table")
                .filter_map(Result::ok)
                .all(|entry| {
                    let metadata = entry.metadata().expect("child descriptor metadata");
                    DescriptorObject {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        file_type: metadata.mode() & libc::S_IFMT,
                    } != boot_object
                }),
            "the manager-opened boot descriptor must not enter the selected child"
        );
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
