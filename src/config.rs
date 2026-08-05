// Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
// You may not use this file except in compliance with that License.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

pub(crate) const AUTHORITY_LAUNCHER_CONFIG_PATH: &str = "/etc/ota/authority-launcher.json";
pub(crate) const CROSSING_BROKER_STORE_PATH: &str = "/etc/ota/crossing-brokers.json";

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("protected launcher configuration is unavailable")]
    Unavailable,
    #[error("protected launcher configuration is malformed")]
    Malformed,
    #[error("protected launcher configuration failed filesystem verification")]
    Unprotected,
    #[error("protected launcher configuration contains an unsupported value")]
    Unsupported,
    #[error("the requested authority has no unique protected launcher session")]
    AuthorityUnavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherConfig {
    pub schema_version: u32,
    pub ota_binary: PathBuf,
    pub run_as: RunAs,
    pub environment: BTreeMap<String, String>,
    pub sessions: Vec<LauncherSessionBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherSessionBinding {
    pub authority_id: String,
    pub broker_session_descriptor: i32,
    pub expected_peer: SessionPeer,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionPeer {
    pub uid: u32,
    pub gid: u32,
}

impl LauncherConfig {
    pub(crate) fn session(
        &self,
        authority_id: &str,
    ) -> Result<&LauncherSessionBinding, ConfigError> {
        let mut matches = self
            .sessions
            .iter()
            .filter(|session| session.authority_id == authority_id);
        let selected = matches.next().ok_or(ConfigError::AuthorityUnavailable)?;
        if matches.next().is_some() {
            return Err(ConfigError::AuthorityUnavailable);
        }
        Ok(selected)
    }
}

#[derive(Debug, Deserialize)]
struct CoreBrokerStore {
    schema_version: u32,
    bindings: Vec<CoreBrokerBinding>,
}

#[derive(Debug, Deserialize)]
struct CoreBrokerBinding {
    authority_id: String,
    credential_delivery: CoreCredentialDelivery,
}

#[derive(Debug, Deserialize)]
struct CoreCredentialDelivery {
    kind: String,
    descriptor: i32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreBindingSelection {
    pub ota_session_descriptor: i32,
}

pub(crate) fn load_launcher_config(path: &str) -> Result<LauncherConfig, ConfigError> {
    let path = Path::new(path);
    let file = open_protected_file(path, 0, Path::new("/"))?;
    let config: LauncherConfig =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| ConfigError::Malformed)?;
    validate_launcher_config(&config)?;
    verify_protected_executable(config.ota_binary.as_path(), 0, Path::new("/"))?;
    Ok(config)
}

pub(crate) fn load_core_binding(
    path: &str,
    authority_id: &str,
) -> Result<CoreBindingSelection, ConfigError> {
    let file = open_protected_file(Path::new(path), 0, Path::new("/"))?;
    let store: CoreBrokerStore =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| ConfigError::Malformed)?;
    if store.schema_version != 1 {
        return Err(ConfigError::Unsupported);
    }
    let mut matches = store
        .bindings
        .iter()
        .filter(|binding| binding.authority_id == authority_id);
    let selected = matches.next().ok_or(ConfigError::AuthorityUnavailable)?;
    if matches.next().is_some()
        || selected.credential_delivery.kind != "launcher_session_fd"
        || selected.credential_delivery.descriptor < 3
    {
        return Err(ConfigError::AuthorityUnavailable);
    }
    Ok(CoreBindingSelection {
        ota_session_descriptor: selected.credential_delivery.descriptor,
    })
}

fn validate_launcher_config(config: &LauncherConfig) -> Result<(), ConfigError> {
    if config.schema_version != 1
        || !config.ota_binary.is_absolute()
        || config.run_as.uid == 0
        || config.run_as.gid == 0
        || config.environment.keys().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
        || config.sessions.is_empty()
    {
        return Err(ConfigError::Unsupported);
    }
    let mut authorities = BTreeSet::new();
    let mut descriptors = BTreeSet::new();
    for session in &config.sessions {
        if session.authority_id.is_empty()
            || session.authority_id.len() > 128
            || !session
                .authority_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || session.broker_session_descriptor < 3
            || !authorities.insert(session.authority_id.as_str())
            || !descriptors.insert(session.broker_session_descriptor)
        {
            return Err(ConfigError::Unsupported);
        }
    }
    Ok(())
}

fn open_protected_file(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<File, ConfigError> {
    verify_protected_path(path, expected_uid, trusted_root, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::Unavailable)?;
    let opened = file.metadata().map_err(|_| ConfigError::Unavailable)?;
    let observed = path.metadata().map_err(|_| ConfigError::Unavailable)?;
    if opened.dev() != observed.dev() || opened.ino() != observed.ino() {
        return Err(ConfigError::Unprotected);
    }
    Ok(file)
}

fn verify_protected_executable(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<(), ConfigError> {
    verify_protected_path(path, expected_uid, trusted_root, true)
}

fn verify_protected_path(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
    executable: bool,
) -> Result<(), ConfigError> {
    if !path.is_absolute() || !trusted_root.is_absolute() || !path.starts_with(trusted_root) {
        return Err(ConfigError::Unprotected);
    }
    let mut current = Some(path);
    while let Some(candidate) = current {
        let metadata = candidate
            .symlink_metadata()
            .map_err(|_| ConfigError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(ConfigError::Unprotected);
        }
        if candidate == path {
            if !metadata.is_file()
                || (executable && (metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0))
            {
                return Err(ConfigError::Unprotected);
            }
        } else if !metadata.is_dir() {
            return Err(ConfigError::Unprotected);
        }
        if candidate == trusted_root {
            return Ok(());
        }
        current = candidate.parent();
    }
    Err(ConfigError::Unprotected)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn launcher_config_rejects_duplicate_authority_and_root_target() {
        let config = LauncherConfig {
            schema_version: 1,
            ota_binary: PathBuf::from("/usr/local/bin/ota"),
            run_as: RunAs { uid: 0, gid: 1000 },
            environment: BTreeMap::new(),
            sessions: vec![LauncherSessionBinding {
                authority_id: String::from("release"),
                broker_session_descriptor: 4,
                expected_peer: SessionPeer { uid: 0, gid: 0 },
            }],
        };
        assert!(validate_launcher_config(&config).is_err());

        let config = LauncherConfig {
            run_as: RunAs {
                uid: 1000,
                gid: 1000,
            },
            sessions: vec![
                LauncherSessionBinding {
                    authority_id: String::from("release"),
                    broker_session_descriptor: 4,
                    expected_peer: SessionPeer { uid: 0, gid: 0 },
                },
                LauncherSessionBinding {
                    authority_id: String::from("release"),
                    broker_session_descriptor: 5,
                    expected_peer: SessionPeer { uid: 0, gid: 0 },
                },
            ],
            ..config
        };
        assert!(validate_launcher_config(&config).is_err());
    }

    #[test]
    fn protected_file_verifier_rejects_symlink_and_writable_parent() {
        let root = tempdir().expect("temp root");
        let uid = unsafe { libc::geteuid() };
        let protected = root.path().join("protected");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("protected permissions");
        let file = protected.join("config.json");
        fs::write(&file, b"{}").expect("protected file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("file permissions");
        assert!(verify_protected_path(&file, uid, root.path(), false).is_ok());

        let alias = protected.join("alias.json");
        std::os::unix::fs::symlink(&file, &alias).expect("symlink");
        assert!(verify_protected_path(&alias, uid, root.path(), false).is_err());

        fs::set_permissions(&protected, fs::Permissions::from_mode(0o722))
            .expect("writable permissions");
        assert!(verify_protected_path(&file, uid, root.path(), false).is_err());
    }

    #[test]
    fn protected_executable_rejects_privilege_bits() {
        let root = tempdir().expect("temp root");
        let uid = unsafe { libc::geteuid() };
        let executable = root.path().join("ota");
        fs::write(&executable, b"binary").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o4755))
            .expect("setuid permissions");
        assert!(verify_protected_executable(&executable, uid, root.path()).is_err());
    }
}
