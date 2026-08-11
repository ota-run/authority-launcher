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

//! Closed-profile observation assembly for the separated protected-attestation producer.
//!
//! This module owns completeness and ordering only. A probe implementation must establish each
//! fact from its canonical kernel, systemd, filesystem, account, policy, or process-access source.
//! Missing facts refuse; callers cannot inject a partial or pre-labelled observation vector.

use ota_authority_protocol::{
    RuntimeBoundaryObservationState, SystemdJobPrincipalObservation,
    SystemdJobPrincipalRequirementDefinition, SystemdLauncherEvidenceSource,
    SystemdLauncherObservation, SystemdProtectedLauncherInstanceEvidenceV1,
    SystemdProtectedLauncherInstanceEvidenceV2, systemd_job_principal_profile_v1,
    systemd_launcher_profile_identity, systemd_launcher_profile_v2,
    systemd_protected_launcher_instance_identity, systemd_protected_launcher_instance_v2_identity,
};
use thiserror::Error;

const VERIFIED_REASON_CODE: &str = "verified_by_systemd_protected_launcher_v2";

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObservationCollectionError {
    #[error("the protected launcher instance foundation is invalid")]
    InvalidInstance,
    #[error("a required launcher observation is unavailable")]
    LauncherObservationUnavailable,
    #[error("a required job-principal observation is unavailable")]
    JobPrincipalObservationUnavailable,
}

/// Canonical probe boundary. Implementations return success only after checking the named source;
/// they do not return caller-authored status or reason text.
pub trait ClosedProfileProbe: sealed::Sealed {
    fn verify_launcher_source(
        &mut self,
        source: SystemdLauncherEvidenceSource,
    ) -> Result<(), ObservationCollectionError>;

    fn verify_job_principal_requirement(
        &mut self,
        requirement: &SystemdJobPrincipalRequirementDefinition,
    ) -> Result<(), ObservationCollectionError>;
}

pub fn collect_closed_profile(
    mut instance_v1: SystemdProtectedLauncherInstanceEvidenceV1,
    probe: &mut impl ClosedProfileProbe,
) -> Result<SystemdProtectedLauncherInstanceEvidenceV2, ObservationCollectionError> {
    let launcher_profile = systemd_launcher_profile_v2();
    instance_v1.systemd_launcher_profile_identity =
        systemd_launcher_profile_identity(&launcher_profile)
            .map_err(|_| ObservationCollectionError::InvalidInstance)?;
    instance_v1.identity = systemd_protected_launcher_instance_identity(&instance_v1)
        .map_err(|_| ObservationCollectionError::InvalidInstance)?;

    let mut launcher_observations = Vec::with_capacity(launcher_profile.evidence_sources.len());
    for source in launcher_profile.evidence_sources {
        probe.verify_launcher_source(source)?;
        launcher_observations.push(SystemdLauncherObservation {
            source,
            state: RuntimeBoundaryObservationState::Verified,
            reason_code: VERIFIED_REASON_CODE.into(),
        });
    }

    let principal_profile = systemd_job_principal_profile_v1();
    let mut job_principal_observations = Vec::with_capacity(principal_profile.requirements.len());
    for requirement in principal_profile.requirements {
        probe.verify_job_principal_requirement(&requirement)?;
        job_principal_observations.push(SystemdJobPrincipalObservation {
            requirement: requirement.requirement,
            evidence_methods: requirement.evidence_methods,
            state: RuntimeBoundaryObservationState::Verified,
            reason_code: VERIFIED_REASON_CODE.into(),
        });
    }

    let mut complete = SystemdProtectedLauncherInstanceEvidenceV2 {
        schema_version: 2,
        identity: String::new(),
        instance_v1,
        launcher_observations,
        job_principal_observations,
    };
    complete.identity = systemd_protected_launcher_instance_v2_identity(&complete)
        .map_err(|_| ObservationCollectionError::InvalidInstance)?;
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use ota_authority_protocol::{
        LauncherPrincipalMappingV1, OtaProcessPostureV1, SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1,
        SystemdJobPrincipalRequirement, SystemdProtectedLauncherInstanceEvidenceV1,
        UnixPrincipalIdentity, launcher_principal_mapping_identity, ota_process_posture_identity,
        systemd_job_principal_profile_identity, systemd_job_principal_profile_v1,
        systemd_launcher_profile_identity, systemd_launcher_profile_v2,
    };

    use super::*;

    struct RecordingProbe {
        launcher_calls: Vec<SystemdLauncherEvidenceSource>,
        job_calls: Vec<SystemdJobPrincipalRequirement>,
        fail_launcher_at: Option<usize>,
        fail_job_at: Option<usize>,
    }

    impl sealed::Sealed for RecordingProbe {}

    impl ClosedProfileProbe for RecordingProbe {
        fn verify_launcher_source(
            &mut self,
            source: SystemdLauncherEvidenceSource,
        ) -> Result<(), ObservationCollectionError> {
            self.launcher_calls.push(source);
            if self.fail_launcher_at == Some(self.launcher_calls.len() - 1) {
                return Err(ObservationCollectionError::LauncherObservationUnavailable);
            }
            Ok(())
        }

        fn verify_job_principal_requirement(
            &mut self,
            requirement: &SystemdJobPrincipalRequirementDefinition,
        ) -> Result<(), ObservationCollectionError> {
            self.job_calls.push(requirement.requirement);
            if self.fail_job_at == Some(self.job_calls.len() - 1) {
                return Err(ObservationCollectionError::JobPrincipalObservationUnavailable);
            }
            Ok(())
        }
    }

    #[test]
    fn collector_emits_only_the_complete_ordered_separated_producer_profile() {
        let mut probe = RecordingProbe {
            launcher_calls: Vec::new(),
            job_calls: Vec::new(),
            fail_launcher_at: None,
            fail_job_at: None,
        };
        let collected = collect_closed_profile(instance(), &mut probe).expect("complete profile");
        assert_eq!(
            probe.launcher_calls,
            systemd_launcher_profile_v2().evidence_sources
        );
        assert_eq!(
            probe.job_calls,
            systemd_job_principal_profile_v1()
                .requirements
                .into_iter()
                .map(|value| value.requirement)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            collected.instance_v1.systemd_launcher_profile_identity,
            systemd_launcher_profile_identity(&systemd_launcher_profile_v2())
                .expect("profile identity")
        );
    }

    #[test]
    fn collector_refuses_before_labelling_a_partial_profile_verified() {
        let mut missing_launcher = RecordingProbe {
            launcher_calls: Vec::new(),
            job_calls: Vec::new(),
            fail_launcher_at: Some(3),
            fail_job_at: None,
        };
        assert_eq!(
            collect_closed_profile(instance(), &mut missing_launcher),
            Err(ObservationCollectionError::LauncherObservationUnavailable)
        );
        assert!(missing_launcher.job_calls.is_empty());

        let mut missing_job = RecordingProbe {
            launcher_calls: Vec::new(),
            job_calls: Vec::new(),
            fail_launcher_at: None,
            fail_job_at: Some(4),
        };
        assert_eq!(
            collect_closed_profile(instance(), &mut missing_job),
            Err(ObservationCollectionError::JobPrincipalObservationUnavailable)
        );
    }

    fn instance() -> SystemdProtectedLauncherInstanceEvidenceV1 {
        let identity = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let principal = |uid: u32, gid: u32| UnixPrincipalIdentity {
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
            job_peer: principal(1001, 1001),
            execution: principal(2001, 2001),
            job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job profile identity"),
            launcher_session_binding_identity: identity('a'),
        };
        mapping.identity = launcher_principal_mapping_identity(&mapping).expect("mapping identity");
        let mut posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: ota_authority_protocol::OTA_PROCESS_POSTURE.into(),
            pid: 42,
            process_start_time_identity: identity('b'),
            ota_binary_identity: identity('c'),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: mapping.identity.clone(),
        };
        posture.identity = ota_process_posture_identity(&posture).expect("posture identity");
        SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: mapping,
            process_posture: posture,
            systemd_launcher_profile_identity: identity('d'),
            systemd_job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v1(),
            )
            .expect("job profile identity"),
            launcher_session_binding_identity: identity('a'),
            systemd_invocation_identity: identity('e'),
            working_directory_identity: identity('f'),
            child_process_identity: identity('1'),
        }
    }
}
