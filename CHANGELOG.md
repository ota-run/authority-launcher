<!--
   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.

   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
   You may not use this file except in compliance with that License.
-->

# Changelog

## Unreleased

### Added

- Add the initial Unix session-isolating launcher wrapper for Ota broker crossing authority.
- Load launcher and Core broker selection only from fixed, protected system configuration.
- Verify the administrator-supplied connected Unix stream and prevent broker or unrelated file
  descriptors from surviving child execution.
- Start one fixed Ota binary as a configured non-root principal with Linux `no_new_privs`,
  parent-death signaling, and bounded process/session cleanup.
- Add a contract-owned Linux/macOS verification matrix pinned to an exact Ota Core revision.

### Boundaries

- The current implementation does not create launcher attestations, connect to a remote broker,
  issue or consume leases, or establish provider-attested authority separation.
