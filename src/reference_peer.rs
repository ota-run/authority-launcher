// Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
// You may not use this file except in compliance with that License.

//! Test-only one-use lease state for launcher transport pressure.
//!
//! This is deliberately not a production broker. It provides deterministic atomic-consumption
//! semantics for adversarial launcher tests without moving approval policy into this repository.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsumeState {
    Consumed,
    AlreadyConsumed,
    Expired,
    Revoked,
    OutOfScope,
}

#[derive(Debug)]
struct Lease {
    scope_identity: String,
    live: bool,
}

#[derive(Debug, Default)]
struct StoreState {
    leases: BTreeMap<String, Lease>,
    consumed: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ReferenceLeaseStore {
    state: Mutex<StoreState>,
}

impl ReferenceLeaseStore {
    pub(crate) fn issue(&self, lease_id: &str, scope_identity: &str, live: bool) {
        self.state.lock().expect("lease lock").leases.insert(
            lease_id.to_string(),
            Lease {
                scope_identity: scope_identity.to_string(),
                live,
            },
        );
    }

    pub(crate) fn revoke(&self, lease_id: &str) {
        if let Some(lease) = self
            .state
            .lock()
            .expect("lease lock")
            .leases
            .get_mut(lease_id)
        {
            lease.live = false;
        }
    }

    pub(crate) fn consume(&self, lease_id: &str, scope_identity: &str) -> ConsumeState {
        let mut state = self.state.lock().expect("lease lock");
        let Some(lease) = state.leases.get(lease_id) else {
            return ConsumeState::Expired;
        };
        if lease.scope_identity != scope_identity {
            return ConsumeState::OutOfScope;
        }
        if !lease.live {
            return ConsumeState::Revoked;
        }
        if !state.consumed.insert(lease_id.to_string()) {
            return ConsumeState::AlreadyConsumed;
        }
        ConsumeState::Consumed
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn lease_consumption_is_atomic_and_exact_scope() {
        let store = Arc::new(ReferenceLeaseStore::default());
        store.issue("lease-live", "scope-a", true);
        let handles = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                thread::spawn(move || store.consume("lease-live", "scope-a"))
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("consumer"))
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|state| **state == ConsumeState::Consumed)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|state| **state == ConsumeState::AlreadyConsumed)
                .count(),
            7
        );

        store.issue("lease-scope", "scope-a", true);
        assert_eq!(
            store.consume("lease-scope", "scope-b"),
            ConsumeState::OutOfScope
        );
        store.issue("lease-revoked", "scope-a", true);
        store.revoke("lease-revoked");
        assert_eq!(
            store.consume("lease-revoked", "scope-a"),
            ConsumeState::Revoked
        );
        assert_eq!(
            store.consume("lease-missing", "scope-a"),
            ConsumeState::Expired
        );
    }
}
