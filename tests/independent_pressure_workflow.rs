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
    assert!(WORKFLOW.contains("expected_authority_state_paths"));
    assert!(WORKFLOW.contains("/run/ota/authority-history.sock"));
    assert!(WORKFLOW.contains("prepared runner publication gate is invalid"));
    assert!(WORKFLOW.contains("core_source_revision == $commit"));
    assert!(!WORKFLOW.contains("core_source_revision | startswith"));
    assert!(WORKFLOW.contains("job-principal process escaped protected runner cgroup"));
}
