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

- Add the Launcher side of the production systemd operator attachment. The new
  `ota-authority-systemd-client` uses only the fixed protected-launcher socket, admits only governed
  Ota execution commands, preserves globally ordered output, verifies terminal evidence, and uses
  exact finalization recovery without pressure-only controls. A separate fixed protected-history
  service now admits only the installed least-privilege client, binds the exact live peer and
  administrator-owned repository mapping, and streams acyclic Protocol records for three protected
  content-addressed objects: receipt archive, referenced immutable contract snapshot, and signed
  sidecar. The binding must name the canonical
  `/var/lib/ota/authority-launcher/history/{blobs,catalog}` roots; alternate protected roots refuse.
  The service repeats complete least-privilege process, executable, working-directory, and peer-
  identity admission before its first response and terminal completion. Launcher publishes those
  objects and their catalog entry durably before repository sidecar acknowledgement or terminal-
  journal deletion. The coordinated Core consumer is implemented in the same V11.7 delivery batch,
  and both consumers pin Protocol commit `04a199a1eddd72b5b61958e0fe7f2d4e662e05cf`.
  Installed PID 1 deployment and hosted pressure remain open.

- Make completion-crash recovery evidence explicit. A restarted launcher may bind verified child
  absence to Core's durable completion, but it cannot claim that it observed or reaped the old
  child. Recovered finalization therefore uses protocol schema v2 with
  `recovered_absent_completion_bound`, no observed exit code, and `child_reaped: false`; live
  finalization retains the original observed-and-reaped posture. Immutable Linux/x64 PID 1
  [run 31758094819](https://github.com/ota-run/authority-launcher/actions/runs/31758094819)
  proves the corrected portable-finalization and crash-recovery matrix against immutable Protocol,
  Core, and Launcher revisions, including valid archive history and zero terminal boundary residue.

- Add the candidate durable post-cleanup finalization carrier. Before deleting the active-slot
  journal, the launcher fsyncs a separate protected finalization intent. The attestor signs both
  exact cleanup evidence and a distinct attachment binding that evidence to the exact receipt
  archive and crossing transaction. The root launcher reopens the exact private archive through the
  execution-principal repository descriptor, verifies its owner, content identity, and transaction,
  then atomically publishes the root-owned sidecar. The job principal can only acknowledge that
  exact signed result. The launcher retains the exact terminal frame until a separate
  identity-bound terminal acknowledgement, so a lost terminal response remains replayable. The
  `.ota` and receipt directories must be execution-principal-owned and mode `0700`. The launcher
  unit now binds `CAP_DAC_OVERRIDE` exactly, without granting it ambiently, so the root
  launcher can traverse that private hierarchy for archive verification and sidecar publication;
  its protected mount namespace, inaccessible signing-key paths, explicit writable roots, and
  exact archive checks remain required. Every
  intermediate stage remains restart-readable, including reconnect before the client has received
  finalization. Startup now promotes an exact execution-completion slot into the same durable
  finalization intent before removing the active slot, so a launcher crash after selected work
  cannot force a second work unit. Local regressions cover retained state and alias refusal;
  immutable PID 1 crash pressure is green in run `31758094819`, while a production operator client
  remains required before shipment.

- Enable the first bounded selected-execution path for `systemd_protected_launcher/v1`. Core keeps
  the private launcher session through terminal transaction finalization and sends one completion
  binding the consumed lease, work unit, pending transaction, terminal transaction, outcome, and
  receipt status. The launcher fsyncs that completion before acknowledgement, relays bounded
  sequenced output, reconciles the actual child exit, and emits terminal evidence only after exact
  scope removal, empty or absent cgroup confirmation, child reaping, and active-slot removal.
  A launcher readiness challenge ensures credential and pidfd ancillary capture is enabled before
  the broker proxy sends its authenticated identity preface.
  Refusal and uncertain-cleanup paths remain fail-closed. Immutable Linux/x64 PID 1 pressure run
  [31664495937](https://github.com/ota-run/authority-launcher/actions/runs/31664495937)
  proves completed, failed, interrupted, replay-refused, and crash-recovered selected execution
  against Launcher `e8b6ae5108559508cfb75141cb9b317d46c182f3`, Core
  `06976f3eb4919a0bddaa318ed0824a6b9448aaaf`, and Protocol
  `9fb00a4ab0f1b4c635dbab67c2e6b140b8eade9c`. Portable archive binding of
  launcher finalization remains open.

- Extend the execution-disabled protected systemd foundation through one exact prepared-lease and
  consumed-response relay. The launcher durably journals the exact transaction-bound intent and
  consumed relay, while Core verifies that protected persistence in private in-memory transaction
  state before acknowledging it. The pressure broker now atomically records spent lease identities
  in root-owned durable state and produces a signed `already_consumed` response for an exact replay;
  the hosted workflow requires that response to bind the original lease and consume request while
  Core accepts only the first consumption. The exact scope is still removed before selected work.
  Immutable Linux/x64 PID 1 systemd run
  [31631358796](https://github.com/ota-run/authority-launcher/actions/runs/31631358796) proves this
  bounded path against Launcher `2185682777c3603ae428dda68d47b1e39d709753`, clean source-built
  Core `874c5954798453f92a0141bfc964fe1a90db8d92`, and Protocol
  `899718c93f205eea8ae403e041be9449daa89192`. This remains execution-disabled foundation work: it
  does not enable repository execution or crossing receipts/archives, and broker-process restart
  persistence is not separately pressure-proven.

- Derive ordinary CI and root-boundary source-identity assertions from the contract-selected setup
  result instead of duplicating a historical Core revision. Both lanes still require a clean source
  build and reconcile the installed binary's reported commit, while contract pin advances no longer
  leave a contradictory workflow-owned pin behind.
- Keep pressure-only Linux observation labels available to the fault-enabled diagnostics without
  leaving unused bindings in the default production build, restoring strict default-feature Clippy
  after the repaired source-identity gate exposed the downstream failure.
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
