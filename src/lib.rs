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

#[cfg(target_os = "linux")]
pub mod attestation_client;
#[cfg(feature = "protected-attestor")]
pub mod attestor;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Shared protected verifier loading for the Step 7 observation service.
pub(crate) mod config;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
// Shared protected installation reconciliation for the Step 7 observation service.
pub(crate) mod installation_manifest;
#[cfg(target_os = "linux")]
pub mod linux_observations;
#[cfg(target_os = "linux")]
pub mod observation_collector;
#[cfg(all(target_os = "linux", feature = "protected-attestor"))]
#[allow(dead_code)] // Step 7 protected observation route; provider operations remain inactive.
pub(crate) mod protected_capability_observation;
#[cfg(target_os = "linux")]
// The protected Launcher observation service remains the only production caller.
#[allow(dead_code)]
pub(crate) mod protected_launcher_capability;
#[cfg(target_os = "linux")]
pub mod systemd_client;
