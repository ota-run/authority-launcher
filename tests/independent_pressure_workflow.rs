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

const WORKFLOW: &str =
    include_str!("../.github/workflows/systemd-v3-independently-administered.yml");
const RECOVERY_WORKFLOW: &str =
    include_str!("../.github/workflows/systemd-v3-independently-administered-recovery.yml");
const RECOVERY_TRIGGER_WORKFLOW: &str =
    include_str!("../.github/workflows/systemd-v3-independently-administered-recovery-trigger.yml");

#[test]
fn independent_pressure_workflow_retains_a_narrow_drift_guard() {
    // This is review-oriented drift detection for the committed workflow, not a sandbox. Runtime
    // separation comes from the protected runner principal, systemd unit, and authority paths.
    for forbidden in [
        "actions/checkout",
        "rust-toolchain",
        "cargo ",
        "sudo",
        "systemctl",
        "useradd",
        "groupadd",
        "chmod",
        "chown",
        "LoadCredential",
        "secrets.",
        "credential",
        "tee /etc/",
        "tee /var/lib/",
    ] {
        assert!(
            !WORKFLOW.contains(forbidden),
            "consumer workflow contains forbidden authority operation: {forbidden}"
        );
    }

    assert!(WORKFLOW.contains("workflow_dispatch:"));
    assert!(!WORKFLOW.contains("pull_request:"));
    assert!(WORKFLOW.contains("ota-authority-independent"));
    assert!(WORKFLOW.contains("/usr/lib/ota-authority/bin/ota-authority-systemd-client"));
    assert!(WORKFLOW.contains("/usr/share/ota/authority-launcher/installation-evidence.json"));
    assert!(WORKFLOW.contains("--source systemd_protected_launcher"));
    assert!(WORKFLOW.contains("/etc/systemd/system/ota-authority-pressure-runner.service"));
    assert!(WORKFLOW.contains("repository entry is writable or aliased"));
    assert!(WORKFLOW.contains("installation evidence ownership chain is invalid"));
    assert!(WORKFLOW.contains("prepared_provisioning_observation"));
    assert!(WORKFLOW.contains("fresh_managed_authority_state"));
    assert!(WORKFLOW.contains("root_owned_non_writable_directory_chain_without_aliases"));
    assert!(WORKFLOW.contains("inactive_or_not_found_before_mutation"));
    assert!(WORKFLOW.contains("no_loaded_systemd_socket_unit_owns_managed_path_before_mutation"));
    assert!(WORKFLOW.contains("expected_authority_state_paths"));
    assert!(WORKFLOW.contains("/run/ota/authority-history.sock"));
    assert!(WORKFLOW.contains("prepared runner publication gate is invalid"));
    assert!(WORKFLOW.contains("core_source_revision == $commit"));
    assert!(!WORKFLOW.contains("core_source_revision | startswith"));
    assert!(WORKFLOW.contains("job-principal process escaped protected runner cgroup"));
}

#[test]
fn independent_recovery_workflow_is_consumer_only() {
    for forbidden in [
        "actions/checkout",
        "rust-toolchain",
        "cargo ",
        "sudo",
        "systemctl",
        "shutdown -",
        "chmod",
        "chown",
        "secrets.",
        "tee /etc/",
        "tee /var/lib/",
        "pressure-exit-after",
    ] {
        assert!(
            !RECOVERY_WORKFLOW.contains(forbidden),
            "recovery consumer contains administrator operation: {forbidden}"
        );
    }

    assert!(RECOVERY_WORKFLOW.contains("workflow_dispatch:"));
    assert!(!RECOVERY_WORKFLOW.contains("pull_request:"));
    assert!(RECOVERY_WORKFLOW.contains("ota-authority-independent"));
    assert!(RECOVERY_WORKFLOW.contains("WORKFLOW_REVISION: ${{ github.sha }}"));
    assert!(RECOVERY_WORKFLOW.contains("EXPECTED_CORE_REVISION:"));
    assert!(RECOVERY_WORKFLOW.contains("EXPECTED_PROTOCOL_REVISION:"));
    assert!(RECOVERY_WORKFLOW.contains("execution-completion.json"));
    assert!(RECOVERY_WORKFLOW.contains("finalization-intent.json"));
    assert!(RECOVERY_WORKFLOW.contains("terminal-recorded.json"));
    assert!(RECOVERY_WORKFLOW.contains("prepared_state_identity"));
    assert!(RECOVERY_WORKFLOW.contains("retained_record_identity"));
    assert!(RECOVERY_WORKFLOW.contains("expected-archive-identities.json"));
    assert!(RECOVERY_WORKFLOW.contains("--source systemd_protected_launcher"));
    assert!(RECOVERY_WORKFLOW.contains(".summary.archive_count == 3"));
    assert!(RECOVERY_WORKFLOW.contains(".summary.invalid_archive_count == 0"));
}

#[test]
fn independent_recovery_trigger_is_runner_owned_and_non_administrative() {
    for forbidden in [
        "actions/checkout",
        "rust-toolchain",
        "cargo ",
        "sudo",
        "systemctl",
        "shutdown -",
        "chmod",
        "chown",
        "secrets.",
        "tee /etc/",
        "tee /var/lib/",
        "authority-admin-pressure",
        "pressure-exit-after",
        "recovery-controller",
    ] {
        assert!(
            !RECOVERY_TRIGGER_WORKFLOW.contains(forbidden),
            "recovery trigger contains administrator operation: {forbidden}"
        );
    }

    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("workflow_dispatch:"));
    assert!(!RECOVERY_TRIGGER_WORKFLOW.contains("pull_request:"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("ota-authority-independent"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("ota-authority-systemd-client"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("--administrator-controlled-recovery"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("output_incomplete"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("launcher_service_unavailable"));
    assert!(
        RECOVERY_TRIGGER_WORKFLOW.contains("execution_started")
            && RECOVERY_TRIGGER_WORKFLOW.contains("is True")
    );
    assert!(!RECOVERY_TRIGGER_WORKFLOW.contains("selected-work-executed"));
    assert!(RECOVERY_TRIGGER_WORKFLOW.contains("ota-authority-pressure-runner.service"));
}
