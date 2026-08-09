<!--
                █████
               ░░███
       ██████  ███████    ██████
      ███░░███░░░███░    ░░░░░███
     ░███ ░███  ░███      ███████
     ░███ ░███  ░███ ███ ███░░███
     ░░██████   ░░█████ ░░████████
      ░░░░░░     ░░░░░   ░░░░░░░░

   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.

   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.

   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
   You may not use this file except in compliance with the License.
   Unless required by applicable law or agreed to in writing, software distributed under the
   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
   either express or implied. See the License for the specific language governing permissions
   and limitations under the License.

   If you need additional information or have any questions, please email: os@ota.run
-->

# Changelog

## Unreleased

### Added

- Add the initial Unix session-isolating launcher wrapper for Ota broker crossing authority.
- Load launcher and Core broker selection only from fixed, protected system configuration.
- Verify the administrator-supplied connected Unix stream and prevent broker or unrelated file
  descriptors from surviving child execution.
- Bind every protected Unix session to an administrator-declared local peer UID and GID.
- Pin transport conformance tests to the immutable public `ota-authority-protocol` wire model.
- Add a feature-gated, fixed-test-key peer for hosted end-to-end live, expired, revoked,
  wrong-scope, and signed already-consumed refusal pressure through the real launcher and Core
  transaction path. Its paired recovery case now withholds an already-consumed response, then
  proves exact signed status re-query and fresh-lease execution on a second launcher session;
  atomic one-use state remains covered by the reference-store regression.
- Upgrade the pressure carrier to protocol v2 with disjoint broker and attestor keys, an exact
  protected-launcher runtime-boundary profile, and receipt/archive assertions over the signed
  profile. The hosted lane uses a dedicated non-root principal without supplemental groups or
  readable Docker control and keeps the pressure peer root-only. The signer re-observes the live
  child principal, capabilities, environment, unnamed session, protected access, and measured
  launcher state after receiving the frozen challenge.
- Start one fixed Ota binary as a configured non-root principal with Linux `no_new_privs`,
  parent-death signaling, and bounded process/session cleanup.
- Add a contract-owned Linux/macOS verification matrix pinned to an exact Ota Core revision.
- Permit the exact `ota proof runtime` and `ota proof lifecycle` surfaces so one protected launcher
  session can carry Core's proof-wide crossing transaction through terminal cleanup and archive
  reconciliation.
- Extend the execution-disabled Linux systemd service foundation with a root-owned active-slot
  journal created and fsynced before fork, an exact fixed-binary child stopped before privilege
  drop or execution, production verification of its root/stopped posture and complete descriptor
  set, and startup cleanup through a PID-bound handle. Child-bearing temporary state is promoted;
  intent-only, uncertain, or mismatched recovery retains the journal and refuses new work. No code
  path resumes the child.

### Boundaries

- The current implementation does not create launcher attestations, connect to a remote broker,
  issue or consume leases, or establish provider-attested authority separation.
- The systemd service foundation does not create a transient scope, resume its prepared child,
  contact the broker, or execute selected work. Pre-scope recovery requires Linux `pidfd`; when it
  is unavailable or identity cannot be reconciled, the durable slot remains a hard refusal.
- Protocol-v2 attestations are emitted only by the feature-gated pressure peer as bounded
  conformance evidence; they do not establish provider-attested or host-wide isolation.
