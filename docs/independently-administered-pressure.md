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

# Independently Administered Systemd Pressure

This runbook separates authority administration from the repository workflow. It is for the
bounded V11.7 systemd pressure gate, not general production deployment.

The administrator prepares the host, authority material, services, repository mapping, and the
exact protected runner service before enabling the runner. The committed repository workflow
invokes the fixed production client and reads the bounded protected-history response; it contains
no build, install, credential, reconfiguration, restart, or fault-control step. That source-level
constraint is reviewable drift posture, not enforcement against equivalent job code. The non-root
principal, protected service, and inaccessible authority paths provide the runtime boundary.

## Ownership

| Owner | Owns | Must not own |
| --- | --- | --- |
| Administrator | Host image, users, installed binaries, systemd units, authority keys, broker state, repository mapping, runner registration | Repository workflow or selected task behavior |
| Repository workflow | One fixed authority label, one fixed prepared repository, bounded public evidence upload | Root access, service control, authority files, alternate sockets, paths, credentials, or fault controls |
| Selected execution | The declared task under the distinct execution principal | Launcher/history sockets, job identity, authority state, or protected history |

The administrator remains trusted in this profile. Root-owned deployment evidence proves that the
repository job did not self-provision authority; it is not provider attestation.

## Prepare Immutable Inputs

Use reviewed immutable revisions for Protocol, Core, and Launcher. Build on the Linux/x64 host from
clean checkouts, then copy only the resulting binaries into a root-owned staging directory.
Launcher embeds its full clean source revision and the exact Protocol Cargo dependency revision
linked into that provisioning binary; Core exposes its full clean source revision through
`ota --version --json`. Provisioning refuses
when those artifact-derived identities are absent, malformed, or dirty. An administrator-owned
deployment record remains useful context, but it is not source provenance.

The Launcher build must enable only the features needed to provision the pressure environment and
run its installed services:

```bash
cargo build --release --locked --bins --features \
  'protected-attestor protected-attestor-client systemd-pressure-client \
   systemd-v3-pressure-provision systemd-decision-pressure-peer \
   systemd-admin-recovery-pressure'
```

Install the exact clean source-built Core binary separately. Do not download or rebuild Core from
the repository workflow.

## Prepare Principals And Repository

Create distinct non-root accounts:

- `ota-authority-job` runs the protected CI runner and production clients;
- `ota-authority-exec` owns the prepared repository and runs selected work.

The job account must have no sudo rule, Polkit service-control authority, supplemental groups,
effective process capabilities, or access to Docker/host-control sockets. Its runner service must
set `NoNewPrivileges=yes`. The execution account must not be able to connect to either protected
Ota socket.

Create `/srv/ota-v3-pressure` as `ota-authority-exec` and place the reviewed pressure contract
there. Every existing directory and regular file must be owned by that principal, unavailable for
write by the job principal, free of symlink aliases, and singularly linked. The selected `governed`
task must create exactly one `selected-work-executed` file containing `executed`. Remove prior
output and `.ota` state before provisioning.

Install the GitHub Actions runner under `/opt/ota-actions-runner`, configure it with automatic
updates disabled, and create the root-owned unit
`/etc/systemd/system/ota-authority-pressure-runner.service` with
`ExecStart=/opt/ota-actions-runner/bin/Runner.Listener run --startuptype service`,
`User=ota-authority-job`, and
`Group=ota-authority-job`. Its `[Unit]` section must also contain the exact gate
`ConditionPathExists=/usr/share/ota/authority-launcher/installation-evidence.json`. Put the
required hardening properties in the root-owned drop-in
`/etc/systemd/system/ota-authority-pressure-runner.service.d/zzzz-ota-pressure-hardening.conf`.
The service must carry `NoNewPrivileges=yes`, empty supplementary groups and capabilities, the
fixed runner working directory, and only the narrowly required writable runner state. Do not use
the runner's generated `actions.runner.*.service`: Launcher admits the exact canonical unit above,
and every job-principal process must remain inside that unit's cgroup.

## Provision Outside GitHub Actions

Run `systemctl daemon-reload`, confirm the runner remains stopped, then run provisioning as the
host administrator before registering the runner:

```bash
/usr/lib/ota-authority/bin/ota-authority-launcher \
  provision-systemd-v3-pressure \
  --authority-id platform-release-authority \
  --job-user ota-authority-job \
  --execution-user ota-authority-exec \
  --repository-root /srv/ota-v3-pressure \
  --launcher-binary /usr/lib/ota-authority/bin/ota-authority-launcher \
  --attestor-binary /usr/lib/ota-authority/bin/ota-authority-attestor \
  --broker-decision-binary /usr/lib/ota-authority/bin/ota-authority-systemd-decision-peer \
  --ota-binary /usr/lib/ota-authority/bin/ota \
  --pressure-client-binary /usr/lib/ota-authority/bin/ota-authority-systemd-client \
  --prepared-runner-binary /opt/ota-actions-runner/bin/Runner.Listener \
  --production-client
```

The pressure broker remains a bounded conformance fixture. It is not a production authorization
service and must not be presented as one.

Provisioning writes the protected installation manifest under `/etc/ota` and a non-secret public
evidence envelope at:

```text
/usr/share/ota/authority-launcher/installation-evidence.json
```

The public envelope contains those bounded artifact-derived source revisions plus protected paths
and content identities for every installed component; it does not claim source provenance for
other Launcher-package binaries merely from sharing a repository. It contains no private keys or
reusable credentials. The envelope and every parent component are
root-owned and non-writable; the file is regular, singularly linked, mode `0644`, and exists only
so the unprivileged workflow can bind retained evidence to the administrator-installed clients.

## Register The Runner

Register the repository-scoped GitHub Actions runner for `ota-run/authority-launcher` as
`ota-authority-job`, install the canonical unit above, provision while that unit is stopped, then
enable it with these labels:

```text
self-hosted, Linux, X64, ota-authority-independent
```

Keep runner registration, service installation, and service restart outside the repository
workflow. The workflow must never receive an administrator token, signing key, broker credential,
or writable authority path.

Provisioning enforces this ordering before its first authority write. It requires the canonical
runner unit to be loaded but `inactive/dead`, with `MainPID=0` and no control group; requires no
live job- or execution-principal process; and requires every managed Ota authority, state, runtime,
unit, socket, history, and public-evidence path for this installation to be absent. Any prior or
ambiguous filesystem object, including a dangling symlink, refuses instead of being overwritten.
Every existing ancestor of every managed path must be a root-owned, non-writable directory and
must not be a symlink; this is checked without following aliases before the first mutation.
The resulting observation and exact canonical ordered checked-path set, including the protected
history runtime socket, are independently rechecked by the consumer workflow. Runner identities,
principal IDs, and the empty process inventory are identity-bound into the public installation
evidence. The exact runner unit is additionally gated by that evidence file, which is published
only after all protected authority services and state are durable. The
job principal therefore cannot start through the canonical runner service during provisioning;
the gate opens only when provisioning completes.

## Run And Inspect

Dispatch `Systemd V3 independently administered pressure`. The committed workflow:

1. verifies the non-root Linux/x64 job posture and fixed public installation evidence;
2. reconciles the fixed production client and Ota binary against administrator-bound hashes;
3. performs one governed invocation through the fixed launcher socket;
4. requires exact terminal cleanup evidence;
5. re-verifies exactly one protected archive with zero invalid archives; and
6. uploads only bounded public evidence.

Do not call the gate complete until the artifact identifies the exact immutable source revisions,
one completed transaction, one valid protected archive, zero invalid archives, and no protected or
private authority material.

The positive gate is green in immutable Linux/x64 PID 1
[run 31939777636](https://github.com/ota-run/authority-launcher/actions/runs/31939777636)
against Protocol `04a199a1eddd72b5b61958e0fe7f2d4e662e05cf`, clean source-built Core
`634a2c169e083da4e02abd72a7bf29ae388ddf3d`, and Launcher
`ea7480e8d8b8aa214c5602628fb6dfa6382e2088`. The retained artifact binds the exact prepared-runner
precondition and installation identities, one consumed work unit, completed selected execution,
exact terminal cleanup, one valid protected archive, zero invalid archives, and no private key or
reusable credential material. This evidence does not cover the separate recovery matrix below or
provider attestation.

## Separate Administrative Recovery

Crash and reboot controls cannot be driven by the repository workflow without destroying the
separation being tested. A separate administrator-owned controller must arm each fault, restart or
reboot the host, and retain public recovery evidence. The repository workflow may only reconnect
through the fixed production client after the administrator declares the prepared runner ready.

Until that controller matrix is green, this lane proves only the independently prepared positive
path. Provider-attested image identity, host isolation, and administrator independence remain
separate stronger claims.

The pressure-only `ota-authority-systemd-recovery-controller` is the canonical administrator
controller. Install its exact reviewed binary as root at
`/usr/lib/ota-authority/bin/ota-authority-systemd-recovery-controller`. It is not an Ota execution
command, broker, attestor, or authority source. It can only arm the three existing root-owned
one-shot fault markers, retain one fixed invocation, require a host reboot, and publish bounded
non-secret evidence after recovery. Its embedded clean Launcher and linked Protocol revisions must
exactly match the protected installation evidence or it refuses before arming a fault.

The controller persists a `prepared` state before arming a marker. It never impersonates the job
principal or invokes Ota from the administrator's process tree: that would not satisfy the bound
runner-service profile. After `arm`, a dedicated no-checkout workflow invokes the exact production
client from the prepared runner cgroup. The administrator then stops and disables the runner;
`reboot` advances the state to `fault_observed` only after the expected protected launcher
checkpoint exists. If the runner invocation has not consumed the marker, inspect `status` and use
`abort-prepared`. That operation removes the unconsumed marker and pending state only when the
runner remains stopped, both principals have no live processes, no launcher journal or scope
exists, selected work did not advance, and repository truth is unchanged. It refuses instead of
cleaning up when partial execution is possible.

Before the first case, stop and disable the repository runner so no workflow can race the
administrator:

```bash
sudo systemctl disable --now ota-authority-pressure-runner.service
```

Run the three cases in this order. The repository task used for this matrix must append exactly one
`executed` line to `selected-work-executed`; protected history begins empty after prepared
provisioning.

```bash
sudo /usr/lib/ota-authority/bin/ota-authority-systemd-recovery-controller arm \
  --fault execution-completion \
  --authority-id platform-release-authority \
  --repository /srv/ota-v3-pressure \
  --job-user ota-authority-job \
  --expected-execution-count 1 \
  --expected-archive-count 1 -- \
  run governed --grant platform-release-authority --receipt

# Queue the exact trigger while the runner is still stopped, then allow that one job to run.
gh workflow run systemd-v3-independently-administered-recovery-trigger.yml \
  --repo ota-run/authority-launcher
sudo systemctl enable --now ota-authority-pressure-runner.service

# After the trigger reports the expected output_incomplete boundary:
sudo systemctl disable --now ota-authority-pressure-runner.service
sudo /usr/lib/ota-authority/bin/ota-authority-systemd-recovery-controller reboot

# Reconnect as the administrator only after the host returns.
sudo /usr/lib/ota-authority/bin/ota-authority-systemd-recovery-controller verify
```

Repeat with `--fault finalization-intent` and expected counts `2`; then use
`--fault terminal-recorded` and expected counts `3`. Each `arm` operation:

- refuses unless the canonical repository runner is disabled, inactive, dead, and has no main PID;
- creates exactly one fixed root-owned one-shot marker;
- never launches a job-principal process or weakens the bound runner-service profile;
- binds the installation identity, exact Core/Launcher/Protocol revisions, controller binary,
  boot ID, invocation identity, repository manifest, and expected execution/archive counts.

The trigger workflow has no checkout, authority-state, fault-marker, service-control, reboot, or
root capability. It verifies its own process is inside the exact prepared runner cgroup, invokes
only the frozen production-client request with automatic reconnect disabled, requires typed
`output_incomplete` after execution started, and does not read execution-principal output or
receipt state. The root controller alone verifies cumulative execution and archive counts. Queue it
before enabling the runner to minimize the admission window. Any different request may fail the
pressure run, but it cannot satisfy the controller's frozen request and checkpoint identities.

Each `reboot` requires the runner to be disabled, inactive, and free of job/execution-principal
processes, then requires the exact retained checkpoint before restarting the host. Each `verify`
operation requires a changed kernel boot ID, unchanged installation/controller
identity, the exact frozen invocation, one recovery-only client exchange, unchanged repository
truth, the expected cumulative execution/archive counts, zero invalid archives, no residual active
or finalization records, no Ota transient scopes, and complete terminal cleanup. It publishes one
create-new root-owned mode-`0644` record beneath the fixed
`/usr/share/ota/authority-launcher/recovery-evidence` directory, then removes the pending private
controller state. Before acknowledging the recovered terminal to Launcher, the constrained client
hands it to the root controller, which validates and fsyncs a `recovery_observed` state. A crash
therefore leaves either Launcher’s replayable finalization journal or the exact controller-owned
terminal needed to confirm that acknowledgement and finish evidence publication.

After all three cases, re-enable the runner and dispatch
`Systemd V3 independently administered recovery`:

```bash
sudo systemctl enable --now ota-authority-pressure-runner.service
```

The consumer workflow cannot arm faults, restart services, reboot the host, read controller state,
or access authority credentials. It re-derives the three public evidence identities, exact boot
chain, immutable revisions and controller binary, then independently verifies three protected
archives with zero invalid archives. A green consumer artifact proves only this administrator-
controlled systemd reboot/recovery matrix; it does not prove provider attestation.
