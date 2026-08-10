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

- Advance the execution-disabled systemd service through one posture-only child transition. After
  the exact transient scope and active slot are durable, the launcher resumes the child through
  `pidfd`, accepts one bounded `ota_process_posture/v1` frame, and reconciles its semantic identity,
  PID/start time, binary identity, and protected principal mapping before exact cleanup. Missing,
  malformed, oversized, or substituted posture fails closed. Core emits the preface before CLI
  dispatch and blocks for a continuation that this slice never sends; no broker frame is forwarded.
- Add a feature-gated, unprivileged systemd pressure client that retains canonical request and
  terminal identities while accepting only the execution-disabled post-cleanup refusal from the
  fixed launcher socket.
- Require the inherited Unix descriptor to accept connections, reconcile it against the unique
  listening `/proc/net/unix` row without rejecting same-path connection rows, and read scope-owned
  systemd properties from the Scope interface.
- Treat a collected transient scope as terminal only when the exact recorded unit is absent and
  its recorded cgroup is empty or absent, closing the `KillUnit`/`StopUnit` collection race without
  weakening cleanup confirmation.
- Add a compile-time pressure-only, root-owned one-shot crash marker after durable scope recording
  so immutable hosted recovery can prove that the next activation removes the exact stopped child
  and transient scope before accepting another request. Production builds omit this fault path.

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
  intent-only, uncertain, or mismatched recovery retains the journal and refuses new work. This
  initial slice did not resume the child.
- Add the execution-disabled transient-scope boundary. The launcher requests one exact scope from
  the root systemd manager, independently reconciles its fixed slice, controls, cgroup, and sole
  stopped PID, then atomically records that identity before cleanup. Scope-bearing recovery stops
  and observes the scope empty before releasing the principal slot. This scope-only slice still
  did not resume the child.

### Boundaries

- The current implementation does not create launcher attestations, connect to a remote broker,
  issue or consume leases, or establish provider-attested authority separation.
- The systemd service foundation resumes its prepared child only after exact scope persistence and
  only far enough to admit the private process-posture preface. It does not sign V3 attestation,
  contact the broker, consume a lease, or execute selected work. Pre-scope recovery requires Linux
  `pidfd`; scope-bearing recovery additionally requires exact systemd and kernel-cgroup
  reconciliation. Unavailable or uncertain cleanup retains the durable slot and refuses new work.
- Protocol-v2 attestations are emitted only by the feature-gated pressure peer as bounded
  conformance evidence; they do not establish provider-attested or host-wide isolation.
