<!--
   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.

   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
   You may not use this file except in compliance with that License.
-->

# Security Policy

`ota-authority-launcher` is trust-sensitive infrastructure. Please report suspected
vulnerabilities privately to `os@ota.run` before opening a public issue. Include the affected
revision, platform, configuration posture, reproduction steps, and the boundary or evidence claim
you believe can be bypassed. Do not include production credentials, grants, signing material, or
private broker payloads.

## Current security boundary

The current implementation is an early Unix session-isolating exec wrapper. It verifies fixed,
root-owned configuration; accepts an already-connected Unix stream; starts one protected Ota
binary as a configured non-root principal; and prevents the broker descriptor and unrelated open
descriptors from surviving child `exec`. The launcher starts as root, clears the child environment,
supplies only protected configuration values, clears supplementary groups, and drops to the
configured UID and GID before Ota begins.

It does not yet establish a complete authority system. In particular, it does not independently
prove:

- provider or launcher attestation;
- authenticated remote broker transport;
- one-use lease issuance or atomic consumption;
- absence of host-level escalation outside the launched process;
- isolation from Docker sockets, namespace control, or provider credentials; or
- terminal receipt and archive reconciliation beyond what Ota Core verifies.

Operators must not treat this repository's current code or a successful local test as proof of
those properties.

The protected Ota executable is verified through a fixed root-owned path whose complete parent
chain is not group/world writable. Execution is not independently protected from a concurrent
mutation by the trusted root administrator; root compromise remains outside this process-level
boundary.

## Protected material

Never place broker credentials, signing keys, reusable grants, lease material, or trust-store
secrets in this repository, `ota.yaml`, workflow YAML, environment variables inherited by Ota, or
task-visible files. The launcher must receive only an administrator-provisioned connected session.
The selected Ota process and its task descendants must never inherit the source broker descriptor.

## Supported platform posture

The first adapter is Unix-only. Linux is the intended hardened deployment target. macOS is useful
for development and descriptor-isolation tests, but is not a production authority-separation
claim. Unsupported platforms must refuse rather than emulate weaker descriptor behavior.

## Release posture

No production-ready release is published yet. Future release artifacts must be immutable,
signed, reproducible where practical, and accompanied by an SBOM and provenance. Operators remain
responsible for patching the launcher, Ota Core, the base operating system, and the protected
broker/session provider.
