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

# AGENTS.md — ota-authority-launcher

> Scope: AI-agent operating guide for this repo. `ota.yaml` is the execution
> contract source of truth; this file only explains how to work inside it.
> If they conflict, `ota.yaml` is authoritative and CI must consume it.

## 1. What this repo is

Trusted Unix launcher boundary for Ota crossing authority (`application`).
It gives Ota Core a protected, challenge-bound session for independently
authorized work without exposing broker credentials, signing material, or
reusable authority to repository tasks.

- Ota Core owns semantic scope, admission, execution, receipts, archives.
- `authority-protocol` owns wire types, framing, identities.
- This repo owns the privileged launcher side: session isolation, protected
  credential/broker-session handling, challenge-bound attestation collection,
  descriptor isolation, hardened systemd installation/service definitions.
- See `README.md` (execution model, trust boundary, systemd foundation),
  `SECURITY.md` (current boundary + reporting), and
  `docs/independently-administered-pressure.md` (administrator/runbook boundary).

## 2. Contract and toolchain (do not improvise)

- Contract: `ota.yaml` — project `ota-authority-launcher`, Ota minimum
  `1.6.28`, `execution.preferred: native`, `supported: [native]`.
- Rust `1.95.0` via `rust-toolchain.toml` (`minimal` + `clippy` + `rustfmt`),
  edition `2024`, `rust-version = "1.95"`.
- Always resolve the runnable lane first:

  ```sh
  ota tasks --safe --use
  ota run verify --agent
  ```

- CI (`./.github/workflows/ci.yml`, matrix `ubuntu-24.04` + `macos-15`):
  installs contract-selected Ota via `ota-run/setup` (`source: contract`),
  verifies exact source identity (`ota --version --json` must be
  `source_build=true`, `dirty=false`, commit prefix-matches contract rev),
  then runs `ota run verify --agent`.
- Agent surface (`ota.yaml:agent`): `entrypoint: verify`,
  `default_task: verify`, `safe_tasks: [fmt, check, clippy, test, verify]`,
  `verify_after_changes: [verify]`.

## 3. Layout

```text
src/main.rs                    # `run` / `serve-systemd` / `serve-history` / pressure provision CLI
src/lib.rs                     # crate root (mostly linux-gated re-exports)
src/unix.rs src/config.rs      # portable session-isolating exec wrapper + fixed protected config
src/systemd_service.rs src/prepared_child.rs src/systemd_scope.rs
src/active_slot.rs src/finalization_journal.rs src/archive_attachment.rs
src/observation_collector.rs src/closed_profile_observations.rs
src/linux_observations.rs src/systemd_runtime_observations.rs
src/installation_manifest.rs src/target_directory.rs
src/attestation_client.rs src/attestor.rs
src/protected_launcher_capability.rs src/protected_capability_observation.rs
src/protected_authority_snapshot.rs
src/protected_history.rs src/protected_history_service.rs
src/systemd_client.rs
src/pressure_provision.rs      # feature-gated provisioner only
src/reference_peer.rs          # cfg(test) only
src/bin/                       # production client plus feature-gated pressure binaries
tests/independent_pressure_workflow.rs
docs/independently-administered-pressure.md docs/pressure/
build.rs                       # embeds clean commit + protocol rev from Cargo.lock
```

## 4. Canonical verification (use this, nothing else, for routine work)

`verify` aggregates `fmt → check → clippy → test`. It proves the local Rust
suite only — not systemd provisioning, broker authority, attestation, or
selected-work execution.

```sh
ota run verify --agent
```

- Always pass `--locked --all-targets --all-features`. `--all-features` matters:
  default-feature clippy can hide failures in pressure/attestor gates.
- `fmt` is read-only verification. Never run `cargo fmt` (write) unless the
  edit is explicitly intended and reviewed.
- Tests needing root-owned attestor state or spent-lease state are explicit
  root-pressure controls; they do not run in ordinary `verify`.
- A green `verify` is **not** authority issuance, protected deployment,
  provider attestation, or selected-work evidence. Never claim it is.

## 5. Safe vs. forbidden for agents

Writable through the routine agent surface: `src`, `tests`, `docs`,
`README.md`, `CHANGELOG.md`, `Cargo.toml`, `rust-toolchain.toml`.

Protected from routine agent execution: `.github`, `AGENTS.md`, `Cargo.lock`,
`ota.yaml`, `LICENSE`, `SECURITY.md`. Change these only when the user explicitly
requests the governance, dependency, licensing, or security edit, and review the
result separately.

Safe lanes: `fmt`, `check`, `clippy`, `test`, `verify` via
`ota run <task> --agent`.

Forbidden via raw shell (require administrator-owned Linux/systemd env,
see `README.md` + pressure runbook — not agent-safe repo work):

- pressure binaries, systemd provisioners, broker peers, attestors,
  protected history services or protected config
  (e.g. do not hand-invoke `provision-systemd-v3-pressure`,
  `ota-authority-pressure-peer`, `ota-authority-systemd-pressure-client`,
  `ota-authority-attestor`, history sockets, `/etc/ota/*`,
  `/var/lib/ota/*`, `/run/ota/*`);
- `sudo`, `systemctl`, `systemd-run`, socket activation, reboot/fault
  markers (e.g. `/run/ota/authority-launcher-pressure-exit-after-scope`);
- host pressure workflows: `root-boundary.yml`,
  `systemd-v3-execution-disabled.yml`,
  `systemd-v3-independently-administered*.yml`;

## 6. Architecture rules agents must respect

- **Platform:** production systemd carrier is Linux-only. Portable Unix
  wrapper + non-Linux refusal paths must stay build-tested on macOS.
  Unsupported platforms refuse — never emulate weaker descriptor behavior.
- **Fixed config only:** launcher + Core broker selection load only from
  `/etc/ota/authority-launcher.json` and `/etc/ota/crossing-brokers.json`.
  No repo-controlled config flag, env var, workflow YAML, or task input may
  select trust roots, keys, credentials, or transport.
- **Accepted surface only:** `ota run`, `ota up`, `ota proof runtime`,
  `ota proof lifecycle` (see `validate_ota_args` in `src/main.rs`).
  `authority_id` is a bounded non-secret label (`<=128` chars,
  `[A-Za-z0-9-_.]`).
- **Descriptor/session isolation:** one administrator-supplied connected Unix
  stream; fixed Ota binary as configured non-root principal; complete child
  env from protected config; every other FD marked close-on-exec; broker
  descriptor never inherited by Ota/task descendants. Fail closed on any
  process/descriptor/config/session doubt.
- **Protocol relay, not interpretation:** proxy framed Core protocol without
  rewriting signed messages. Core derives/verifies identities, scope,
  freshness, one-use state.
- **Feature gates:** `pressure-peer`, `protected-attestor`,
  `protected-attestor-client`, `systemd-pressure-client`,
  `systemd-pressure-faults`, `systemd-v3-pressure-provision`,
  `systemd-decision-pressure-peer`, `systemd-admin-recovery-pressure`,
  `secret-delivery-pressure`. Gate new privileged code correctly with
  `cfg(target_os = "linux")` and/or the matching feature; keep default
  production build minimal.
- **Binaries** (`src/bin/`, all `required-features`): `ota-authority-pressure-peer`
  (conformance only, fixed test keys — never an operator broker/issuer, never
  installed by default), `ota-authority-systemd-pressure-client`
  (unprivileged pressure side, fixed socket only),
  `ota-authority-attestor` (sole holder of systemd-delivered signing credential),
  `ota-authority-systemd-decision-peer`, `ota-authority-systemd-recovery-controller`
  (administrator reboot/fault matrix only), production
  `ota-authority-systemd-client` (fixed `/run/ota/authority-launcher.sock` only).
- **Protocol pin:** `ota-authority-protocol` is a `git rev` dependency in
  `Cargo.toml`. Changing it is a cross-repo compatibility change: repin Core +
  Launcher together, revalidate together, record the immutable rev. Never use a
  branch reference for review/CI. `build.rs` derives the linked protocol rev
  from `Cargo.lock` — do not hand-edit the embedded identity.
- **What belongs here:** launcher-session impl, credential/broker-session
  handling, attestation collection, process/descriptor isolation, hardened
  installation/service defs, conformance/adversarial tests, signed release
  artifacts/SBOM/provenance/operator guidance.
- **What does not:** contract parsing, semantic-scope derivation, self-issued
  grants, approval policy/UI, shared keys/credentials/grants, bundled
  authority-enabled runner image, governing raw shell outside Ota chokepoints.

## 7. Code conventions

- Every file keeps the Ota ASCII-banner + `Copyright (C) 2026 — 2026, Ota`
  + Apache-2.0 + `os@ota.run` header. Do not alter/remove it.
- `cargo fmt` style; `clippy -D warnings` clean on the full feature surface.
- Fail-closed error handling: missing/malformed/oversized/substituted posture,
  challenge, attestation, decision, lease, or scope state refuses through the
  exact cleanup path (remove child → scope → empty/absent cgroup → slot) and
  never executes selected work.
- Keep observation/profile order canonical where the protocol demands it
  (`closed_profile_observations`, systemd v1–v4 / job-principal v1–v2 sets);
  missing/reordered/failed/substituted observations refuse.
- Keep Linux-only code behind `cfg(target_os = "linux")`; keep pressure-only
  diagnostics behind their feature so the default build stays strict.
- Add/extend tests with source changes: unit tests in-module + conformance in
  `tests/`; assert exact terminal stages, zero residual slots/scopes/cgroups,
  byte-identical repo manifests, and no `.ota`/lease/receipt/key residue where
  applicable.

## 8. Security (see SECURITY.md)

- Report suspected vulns privately to `os@ota.run` (rev, platform, posture,
  repro, bypassed boundary/claim). No public issue first. Never paste
  production credentials, grants, signing material, or broker payloads.
- Never place keys, grants, leases, broker credentials, or trust-store secrets
  in the repo, `ota.yaml`, workflow YAML, env, or task-visible files.
- Root compromise and concurrent root mutation of the verified binary path are
  outside the process-level boundary — do not claim otherwise.
- macOS tests prove descriptor isolation, not production authority separation.
  Provider attestation is optional stronger hardening, not a carrier property.

## 9. Before opening a PR

1. `ota tasks --safe --use`, then `ota run verify --agent` (full feature surface).
2. If you touched the protocol pin, `Cargo.toml`, or systemd profiles: repin +
   revalidate Core/Launcher together and cite the immutable revs + pressure-run
   evidence (or state that hosted PID-1 pressure is still open).
3. Update `CHANGELOG.md` (Unreleased) and `README.md`/`docs/` when behavior,
   profiles, features, or operator steps change.
4. Review every intentional protected-path change separately; confirm no secret
   material was added, no header was removed, and no raw-shell pressure path was introduced.
5. CI must stay green on both `ubuntu-24.04` and `macos-15`; root/systemd
   pressure lanes are maintained separately by administrators.

## 10. References

- `README.md` — implementation boundary, execution model, build/invoke,
  trust boundary, systemd foundation, pressure-run ledger.
- `docs/independently-administered-pressure.md` — administrator vs. workflow
  ownership, provisioning, runner registration, recovery matrix.
- `SECURITY.md`, `CHANGELOG.md`, `ota.yaml`, `Cargo.toml`,
  `rust-toolchain.toml`, `.github/workflows/`.
- Sibling contracts: `ota-run/authority-protocol` (wire model),
  `ota-run/ota` (Core: scope/admission/execution/evidence).

<!-- ota-generated-agent-guidance:start -->
# AGENTS.md

Generated from `./ota.yaml` by `ota agents`.

## Repo

- `project`: `ota-authority-launcher`
- `description`: `Trusted Unix launcher boundary for Ota crossing authority`

## Default Workflow

- `name`: `verify`
- `intent`: `verification`
- `run`: `ota run verify`

## Agent Contract

Use only declared `ota run <task>` paths. If the contract does not model the work you need, stop and request a contract update; do not bypass the agent boundary with raw package-manager, compiler, or test commands.

- `entrypoint`: `verify` (`ota run verify`)
- `default_task`: `verify` (`ota run verify`)
- `safe_tasks`:
  - `fmt` (`ota run fmt`)
  - `check` (`ota run check`)
  - `clippy` (`ota run clippy`)
  - `test` (`ota run test`)
  - `verify` (`ota run verify`)
- `verify_after_changes`:
  - `verify` (`ota run verify`)
- `writable_paths`: `src`, `tests`, `docs`, `README.md`, `CHANGELOG.md`, `Cargo.toml`, `rust-toolchain.toml`
- `protected_paths`: `.github`, `AGENTS.md`, `Cargo.lock`, `ota.yaml`, `LICENSE`, `SECURITY.md`

## Bootstrap

This source-distributed launcher requires the reviewed Ota Core revision below; do not substitute a branch or ambient binary for protected-boundary work.

- `source.kind`: `git_rev`
- `source.rev`: `63297ad95ef156b335a1dfb54090146406077a3f`
- `sh`: `curl -fsSL https://dist.ota.run/install.sh | OTA_GIT_REV=63297ad95ef156b335a1dfb54090146406077a3f sh -s -- --from-git`
- `powershell`: `$env:OTA_GIT_REV='63297ad95ef156b335a1dfb54090146406077a3f'; & ([scriptblock]::Create((irm https://dist.ota.run/install.ps1))) -FromGit`

## Notes

Start with `ota tasks --safe --use`, then run the selected routine lane through
`ota run verify --agent`. The safe surface is limited to local Rust verification.
If Ota does not report a lane callable, stop; do not drop `--agent` or invoke Cargo directly.

Do not invoke pressure binaries, systemd provisioners, broker peers, attestors, protected
history services, or protected configuration through raw shell commands. They require the
administrator-owned Linux/systemd environment described in README.md and are not agent-safe
repository work. A passing `verify` result is not authority issuance, protected deployment,
provider attestation, or selected-work evidence.
<!-- ota-generated-agent-guidance:end -->
