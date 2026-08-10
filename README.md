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

# Ota Authority Launcher

Trusted launcher for [Ota](https://github.com/ota-run/ota) crossing authority. It gives Ota a
protected, challenge-bound session for independently authorized work without exposing broker
credentials, signing material, or reusable authority to repository tasks.

> [!IMPORTANT]
> This repository is in early development. It does not yet provide a production-ready launcher,
> hosted authority service, or supported release artifact.

## Current implementation boundary

The first implementation is a Unix session-isolating exec wrapper. It:

- loads launcher configuration only from `/etc/ota/authority-launcher.json`;
- reconciles the selected authority label with Ota's fixed
  `/etc/ota/crossing-brokers.json` binding;
- accepts one already-connected administrator-supplied Unix stream;
- starts one fixed, protected Ota binary as a configured non-root principal;
- gives Ota only its configured session descriptor and marks every other open descriptor
  close-on-exec; and
- proxies the framed Core protocol without interpreting or rewriting signed messages.

This slice does **not** create launcher attestations, connect to a remote broker, hold signing keys,
or make authorization decisions. The administrator-controlled process that supplies the connected
session remains responsible for authenticated transport and protocol responses. Until that
component is deployed with independently protected credentials and attestation, this launcher is
one authority-system building block rather than a complete authority system.

The feature-gated `ota-authority-pressure-peer` binary is an exception for conformance testing
only. It uses fixed public test keys and deterministic scenarios to exercise protocol v2 through a
real launcher/Core process chain. The hosted lane runs Core as a dedicated non-root principal with
no supplemental groups, no readable Docker socket, root-only pressure-peer access, protected
authority files, and a strict signed protected-launcher profile. Its scenarios prove live
consumption plus expired, revoked, wrong-scope, already-consumed, unavailable, timed-out,
cancelled, and ambiguous
pre-execution refusal. A paired recovery scenario withholds an already-consumed response, then
proves that a fresh launcher session re-queries the exact durable intent, closes the abandoned
transaction without execution, and requires a newly consumed lease before work starts. The
separate reference-store regression proves atomic one-use state. The pressure peer is not installed
by default and must never be used as an operator broker or authority issuer.

Immediately before signing each challenge, the pressure attestor reconciles the live Ota child
through Linux procfs: all UID/GID slots, supplementary groups, capabilities, `no_new_privs`, the
exact launcher environment, the unnamed close-on-exec Unix session, protected-path access, common
host-control sockets, and measured launcher/configuration identities.

This is bounded conformance evidence for the test launcher boundary. It is not provider attestation,
does not establish host-wide isolation, and does not turn the production launcher into an issuer.

## Why it exists

Some repository operations need more than ordinary task admission. Production deployment,
database migration, package publication, infrastructure mutation, signing, and secret rotation may
require an independently issued authorization that is valid for exactly one verified invocation.

Ota Core derives the exact contract and execution scope, verifies authority, executes the selected
work, and archives bounded evidence. The authority launcher owns the privileged boundary that Core
must not carry in a normal repository process:

- protected broker transport or workload credentials;
- challenge-bound runner or provider attestation;
- delivery of one non-inheritable launcher session to Ota; and
- isolation of authority material from selected task processes.

## Execution model

```mermaid
sequenceDiagram
    autonumber
    participant Operator as Protected workflow or operator
    participant Repo as Repository contract
    participant Launcher as authority-launcher
    participant Ota as Ota Core
    participant Broker as Protected authority session
    participant Task as Selected task

    Operator->>Launcher: Select non-secret authority label and Ota command
    Launcher->>Launcher: Verify fixed config, binary, principal, and Unix session
    Launcher->>Ota: Start fixed binary with one inherited session FD
    Repo->>Ota: Select authority_id and governed lane
    Ota->>Ota: Freeze contract, scope, work unit, and nonce
    Ota->>Launcher: Send challenge over protected session
    Launcher->>Broker: Proxy framed challenge
    Broker-->>Launcher: Return signed challenge-bound attestation
    Launcher-->>Ota: Proxy signed attestation
    Ota->>Launcher: Request exact-scope authorization
    Launcher->>Broker: Proxy signed request
    Broker-->>Launcher: Return signed decision and prepared lease
    Launcher-->>Ota: Return signed broker evidence
    Ota->>Ota: Create durable pending crossing transaction
    Ota->>Launcher: Consume lease for exact transaction
    Launcher->>Broker: Atomically consume lease once
    Broker-->>Launcher: Return signed consumption result
    Launcher-->>Ota: Return transaction-bound result

    alt Verification, authorization, or consumption fails
        Ota-->>Repo: Refuse before execution starts
    else Lease is verified as consumed
        Ota->>Task: Execute exact selected work
        Task-->>Ota: Return terminal outcome
        Ota->>Ota: Finalize receipt and archive evidence
    end
```

The launcher does not decide what a repository task means. Ota Core remains the canonical owner of
semantic scope, protocol identities, admission rules, refusal behavior, receipts, and archive
verification.

## Build and invoke

The repository currently supports Rust `1.95.0` on Unix platforms:

```sh
cargo build --release
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The launcher deliberately has no repository-controlled config flag. Its protected configuration
has this initial shape:

```json
{
  "schema_version": 1,
  "ota_binary": "/usr/local/bin/ota",
  "run_as": { "uid": 1001, "gid": 1001 },
  "environment": {
    "HOME": "/home/ota-runner",
    "LANG": "C.UTF-8",
    "LOGNAME": "ota-runner",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER": "ota-runner"
  },
  "sessions": [
    {
      "authority_id": "platform-release-authority",
      "broker_session_descriptor": 4,
      "expected_peer": { "uid": 0, "gid": 0 }
    }
  ]
}
```

The administrator-controlled parent starts the launcher as root and opens the authenticated Unix
stream at descriptor `4`, then executes:

```sh
ota-authority-launcher run \
  --authority-id platform-release-authority \
  -- run publish
```

Only `ota run`, `ota up`, `ota proof runtime`, and `ota proof lifecycle` are accepted. The Ota
binary path, execution principal, complete child environment, source session descriptor, and
Ota-facing descriptor come from protected system configuration, never repository files or
inherited environment variables. The complete Core broker binding format is defined in the
[Broker Crossing Authority reference](https://ota.run/docs/reference/broker-crossing-authority).

## Trust boundary

The launcher is administrator-operated infrastructure outside the repository and job-controlled
filesystem. Repository files, workflow YAML, environment variables, policy packs, and task input
must not select or replace its trust roots, broker credentials, verifier keys, or protected
transport.

Selected task processes must not inherit or reacquire the launcher session. The launcher fails
closed when it cannot establish its local process, descriptor, configuration, or session boundary.
Ota Core verifies signed attestation, freshness, semantic scope, and one-use authorization state.

The target repository declares only an authority identity:

```yaml
governance:
  crossing_authority:
    authority_id: platform-release-authority
```

Administrator-owned protected configuration binds that identity to the launcher and broker. No
usable key, grant, lease, credential, or trust path belongs in `ota.yaml`.

## Systemd service foundation

The Linux `systemd_protected_launcher/v1` service path remains execution-disabled. It accepts only
the fixed socket-activated listener, derives the job peer through `SO_PEERCRED`, opens the allowed
repository through the configured execution principal, and prepares the exact protected Ota binary
as a stopped root child. Before fork it creates and fsyncs a root-owned active-slot intent under
`/var/lib/ota/authority-launcher/active`; after fork it atomically binds the request,
working-directory device/inode, principal mapping, PID/start time, binary identity, and complete
child descriptor boundary.

The execution-disabled Linux pressure unit needs root system-manager access and
`CAP_SYS_PTRACE` so it can re-observe the exact stopped child's protected descriptor posture.
It also reads the host `/proc/net/unix` table to reconcile the inherited socket inode, so a unit
with `PrivateNetwork=yes` cannot establish that observation. These are bounded adapter
requirements, not evidence of provider-attested isolation; the effective unit and capability
posture must remain part of the later signed hardening profile.

The child receives only standard streams, the systemd profile's fixed private Ota session
descriptor, the fixed binary descriptor, and the retained repository descriptor. Production code
re-observes that exact root/stopped posture and descriptor set before recording the child. It then
asks the root systemd manager for one request-derived transient scope in the fixed invocation slice,
confirms the exact unit properties and sole PID through the kernel cgroup, and durably records that
scope. Only after that persistence does the launcher resume the exact PID through `pidfd`, admit one
bounded `ota_process_posture/v1` frame, and reconcile its identity, PID/start time, Ota binary, and
principal mapping to the prepared child. The launcher forwards no broker challenge. It then kills
the complete scope, confirms it absent and its cgroup empty or absent, kills/reaps the child, and
removes the slot.

On startup, retained journals are reconciled before accepting a client. A valid child- or
scope-bearing temporary journal is promoted rather than discarded. Intent-only state remains a
hard refusal because it cannot establish child absence. An exact pre-scope child is terminated
through Linux `pidfd`; a scope-bearing journal additionally requires the exact unit and kernel
cgroup to be stopped and observed empty. PID reuse, identity mismatch, unsupported cleanup, or any
uncertain outcome retains the slot and fails closed.
This foundation resumes Ota only through its private posture preface. It does **not** create or sign
V3 attestation, contact the broker, consume a lease, or execute repository work. Missing, malformed,
oversized, self-inconsistent, or child-mismatched posture fails closed and enters the same exact
cleanup path. Core emits this preface before CLI dispatch and waits for a launcher continuation;
this slice deliberately sends none. OrbStack's systemd currently refuses the real pre-exec PID
attachment with `ENOTTY`; the
implementation remains fail-closed there, and positive posture-plus-scope proof requires the
prepared hardened Linux runner.

The feature-gated `ota-authority-systemd-pressure-client` is the unprivileged side of that positive
kernel proof. It connects only to `/run/ota/authority-launcher.sock`, submits one bounded
`LauncherInvocationRequestV1`, and accepts only the execution-disabled terminal refusal emitted
after the service has confirmed scope and child cleanup. Before sending the request it requires the
fixed socket and parent to have the protected root-owned posture and requires the connected Unix
peer to be root-owned. It cannot select another socket, install configuration, mutate systemd,
provide authority, or enable execution. The binary is not installed as part of the production
launcher.

Immutable crash/recovery pressure may additionally build the launcher with the
`systemd-pressure-faults` feature. In that build only, a root-owned mode-`0600` one-shot marker at
`/run/ota/authority-launcher-pressure-exit-after-scope` terminates the service immediately after
the exact child and scope have been durably journaled. The marker is removed and its parent is
synced before termination. The repository job cannot create the marker; an administrator prepares
it before dispatch. The next socket activation must reconcile and remove that exact boundary
before it can accept another request. Production builds omit the feature and marker behavior.

## What belongs here

- the Unix launcher-session implementation;
- protected credential and broker-session handling;
- challenge-bound attestation collection;
- process and descriptor isolation;
- hardened installation and service definitions;
- protocol conformance and adversarial tests; and
- signed release artifacts, SBOMs, provenance, and operator guidance.

## What does not belong here

- Ota contract parsing or semantic-scope derivation;
- repository-owned authorization or self-issued grants;
- organization approval policy or a hosted approval UI;
- shared signing keys, broker credentials, or production grants;
- a bundled authority-enabled runner image; or
- claims that the launcher governs raw shell execution outside adopted Ota chokepoints.

The authority protocol remains canonically specified and verified by Ota Core. A managed broker,
identity-provider integration, approval workflow, fleet administration, and audit search may be
provided separately; the launcher remains independently inspectable and deployable open-source
infrastructure.

## First milestone

The complete first milestone implements the Unix launcher-session carrier defined by Ota Core:

1. accept one administrator-bound local session;
2. return signed attestation bound to Ota's nonce, scope, and work-unit identity;
3. obtain one exact broker authorization and prepared lease;
4. preserve credentials and the launcher descriptor outside task processes;
5. transparently carry broker-backed atomic one-use consumption and typed refusal; and
6. prove success, replay refusal, expiry, revocation, wrong scope, broker unavailability, bounded
   approval timeout/cancellation/ambiguity, proof-wide transaction finalization, and archive
   reconciliation on a hardened Linux runner.

The proof-wide pressure lane keeps Docker control unavailable to the job principal. Its lifecycle
case uses a deterministic pressure-only Compose control stub to exercise Ota-owned service
selection, assertion ordering, terminal authority, and cleanup. That fixture does not claim Docker
provider behavior; independent provider pressure remains a separate Core evidence boundary.

## Relationship to Ota

- [Ota Core](https://github.com/ota-run/ota) owns the protocol, scope, admission, execution, and
  evidence model.
- [Ota Authority Protocol](https://github.com/ota-run/authority-protocol) publishes the shared
  wire types, fixed domains, framing, identities, and conformance vectors.
- This repository implements the privileged launcher side of that protocol.
- The public operator reference is
  [Broker Crossing Authority (Preview)](https://ota.run/docs/reference/broker-crossing-authority).

## License

Apache License 2.0. See [LICENSE](LICENSE).
