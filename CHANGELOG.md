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

- Derive ordinary CI and root-boundary source-identity assertions from the contract-selected setup
  result instead of duplicating a historical Core revision. Both lanes still require a clean source
  build and reconcile the installed binary's reported commit, while contract pin advances no longer
  leave a contradictory workflow-owned pin behind.
- Advance the protected systemd V3 path through execution-disabled signed authorization-decision
  admission. The installation manifest now binds the pressure broker executable and units; the
  launcher retains the protected broker peer, rechecks its manifest-bound live executable around
  relay traffic, forwards only Core's exact request, relays only signed decisions, requires Core's
  exact verification acknowledgement, and durably journals the relay before cleanup. Allowed
  decisions end at
  `authorization_decision_verified_before_lease_boundary_removed`; denied decisions and malformed,
  stale, wrong-scope, ambiguous, timed-out, or unavailable broker responses remain typed bounded
  refusals. No lease is issued or consumed, no selected work runs, and no receipt/archive is made.
- Add the pressure-only signed decision peer and scenario-specific pressure-client terminal
  expectations. Immutable Linux/x64 PID 1 systemd run
  [31561247605](https://github.com/ota-run/authority-launcher/actions/runs/31561247605), against exact
  Protocol `6a92d8db9d089e44d1980f1871bf6e90eccb9960`, Launcher
  `77ab20aa6ed5e3dd42cc6815ba2de7cd36d543bf`, and clean source-built Core
  `b71b78ca33ea2edd7bb03ceb66c5e1e104217cd9`, covers allowed, denied, stale,
  wrong-scope, pending-timeout, ambiguous, and unavailable-proxy cases with repository and cleanup
  controls. Each negative case requires its exact signed peer checkpoint and acknowledgement count
  rather than accepting a generic protocol refusal. Artifacts retain each public signed decision,
  the public broker verifier binding, and complete bounded relay envelopes for independent
  re-verification. A pressure-only crash after durable decision recording proves cleanup-only
  recovery before a fresh request, and every decision scenario compares its complete repository
  manifest before and after. Retained evidence independently re-verifies the public signed
  decisions and relay/admission identities, while every terminal case has zero active slots/scopes
  and no selected-work, `.ota`, lease, receipt, archive, private-key, or credential residue. This is
  execution-disabled hosted pressure, not production lease consumption, selected execution,
  crossing evidence, or provider-attested separation.
- Run every hosted decision scenario through the same manifest-bound, hardened systemd client
  unit. Its observed-outcome mode accepts only the three execution-disabled decision terminals;
  the workflow still requires each scenario's exact terminal, signed broker checkpoints, relay
  count, cleanup, and repository-mutation controls.
- Treat exact scope disappearance between cleanup observations as terminal only when the recorded
  cgroup is also empty or absent. This closes the denied-decision cleanup race without accepting
  mismatched or uninspectable scope state. The same exact-and-empty fallback covers a child that
  exits between liveness observation and scope verification, as stale or invalid signed decisions
  can cause, while nonempty or substituted boundaries still refuse.
- Authenticate the process that accepts the systemd-activated broker stream with one private
  kernel-credential preface. Launcher now requires matching `SCM_CREDENTIALS` and `SCM_PIDFD`, then
  retains and rechecks that pidfd and the manifest-bound executable around relay traffic. It does
  not mistake PID 1, which owns the activated listener, for the service process that accepted the
  connection. The peer must retain the authenticated session until Launcher closes it after final
  revalidation; an early peer exit remains a refusal.

- Verify protected producer freshness at response receipt rather than before transport. A signed
  response issued across a whole-second boundary can no longer be rejected against a stale
  pre-request clock sample during crash recovery.

- Add the first live Linux job-peer observations for the separated producer path. The systemd
  service now retains a socket-bound close-on-exec pidfd, reconciles the protected UID/GID mapping,
  and requires exact live `/proc` UID/GID slots, empty supplementary groups and
  inheritable/permitted/effective/ambient capabilities, and `NoNewPrivs=1` before repository
  opening or child creation.

- Add the fail-closed closed-profile collector foundation for
  `ota.authority-launcher.systemd/v3`. It reconciles protected installation files, exact systemd
  unit/socket/scope runtime properties, process containment, account/sudo/Polkit posture,
  protected-path and host-socket access, and Ota process-access denial. It emits observations only
  in canonical Protocol order and cannot represent a partial launcher or job-principal profile as
  verified.

- Add the execution-disabled protected V3 attestation producer foundation. The separate
  `ota-authority-attestor` Linux service consumes only its fixed root-owned `SOCK_SEQPACKET`
  listener, verifies the live root launcher peer and protected binding, owns the signing credential
  and clock, derives bounded freshness, persists and fsyncs exact canonical response bytes, and
  returns only an identical unexpired response for an identical request identity. Ancillary
  descriptors, truncation, queued second packets, stale state, binding mismatch, and peer races
  fail closed.
- Add the launcher-side protected producer binding loader and response verifier. It independently
  checks canonical request/response and claims projection, the protected public key, signature,
  audience, key interval, and the narrowest producer/verifier/request freshness bound. The
  execution-disabled systemd path now invokes that separately credentialed producer with the exact
  complete observed profile and relays only the independently verified signed attestation to Core.
- Advance the systemd protected-launcher boundary through one signed V3 attestation bridge. Core's
  exact posture admission now receives an identity-bound launcher continuation, freezes the real
  semantic scope, and sends its broker challenge over the same private descriptor. The launcher
  relays only that challenge and one protocol-valid V3 response, observes Core's exact matching
  authorization request, and deliberately does not forward it. Exact scope, cgroup, child, and
  active-slot cleanup remain mandatory before the typed
  `attestation_admitted_before_authorization_boundary_removed` refusal is emitted.
- Keep the new bridge explicitly execution-disabled. It does not obtain an authorization decision,
  issue or consume a lease, execute selected work, or produce crossing receipt/archive evidence.
  Missing or unprotected proxy state, malformed or substituted V3 evidence, mismatched Core
  authorization admission, and continuation substitution fail closed through the same cleanup
  authority and emit `pre_authorization_protocol_refused_boundary_removed`, not a broker authority
  decision or provider-boundary failure.
- Add an immutable Linux/x64 PID 1 systemd pressure workflow for the complete execution-disabled
  V3 path. It binds the contract-selected Core source build and immutable Protocol dependency,
  proves signed admission plus exact cleanup, and exercises protected-installation drift, runtime
  property drift, missing producer credentials, and crash-after-scope recovery. Run
  [31530832876](https://github.com/ota-run/authority-launcher/actions/runs/31530832876) binds exact
  Protocol `574563d1f69a674960d0b3228c5a13b13bc42c19`, Launcher
  `c69ad3afc6afef0e260a7eeaa4f7340971db50af`, and clean source-built Core
  `31fa95b4d28a8a4971ee3fd65c841d40e54ac4d9`. Retained cursor-isolated evidence confirms exact
  positive/recovery admission, pre-authorization refusal controls, terminal cleanup, a
  byte-identical regular-file manifest, and no selected-work or `.ota` state. It does not claim
  authorization, lease, execution, receipt/archive, or provider attestation.

- In the preceding posture-only slice, advance the execution-disabled systemd service through one
  child transition. After
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
