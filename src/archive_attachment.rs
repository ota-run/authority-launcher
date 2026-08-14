//                █████
//               ░░███
//       ██████  ███████    ██████
//      ███░░███░░░███░    ░░░░░███
//     ░███ ░███  ░███      ███████
//     ░███ ░███  ░███ ███ ███░░███
//     ░░██████   ░░█████ ░░████████
//      ░░░░░░     ░░░░░   ░░░░░░░░
//
//   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
//   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
//
//   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
//   You may not use this file except in compliance with the License.
//   Unless required by applicable law or agreed to in writing, software distributed under the
//   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//   either express or implied. See the License for the specific language governing permissions
//   and limitations under the License.
//
//   If you need additional information or have any questions, please email: os@ota.run

//! Protected receipt-archive lookup and launcher-owned sidecar publication.

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ota_authority_protocol::LauncherFinalizationArchiveSidecarV1;
use sha2::{Digest, Sha256};

const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024;
const OTA_DIRECTORY: &CStr = c".ota";
const CONTRACT_DIRECTORY: &CStr = c"contracts";
const RECEIPT_DIRECTORY: &CStr = c"receipts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrozenAttachmentObject {
    pub(crate) bytes: Vec<u8>,
    pub(crate) content_identity: String,
    pub(crate) owner_uid: u32,
    pub(crate) mode: u32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) link_count: u64,
}

pub(crate) struct ArchiveAttachmentTarget {
    directory: File,
    archive_name: CString,
    sidecar_name: CString,
    pub(crate) sidecar_file_name: String,
    receipt_archive_identity: String,
    expected_owner_uid: u32,
    pub(crate) archive: FrozenAttachmentObject,
    pub(crate) contract_snapshot: FrozenAttachmentObject,
}

pub(crate) fn locate_archive(
    repository_fd: RawFd,
    expected_owner_uid: u32,
    receipt_archive_identity: &str,
    crossing_transaction_identity: &str,
) -> Result<ArchiveAttachmentTarget, String> {
    let directory = open_receipt_directory(repository_fd, expected_owner_uid)?;
    let mut matches = Vec::new();
    let directory_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let entries = fs::read_dir(&directory_path)
        .map_err(|_| String::from("the protected receipt archive directory is unavailable"))?;
    for entry in entries {
        let entry = entry
            .map_err(|_| String::from("the protected receipt archive directory is unreadable"))?;
        let name = entry.file_name();
        if Path::new(&name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("json")
        {
            continue;
        }
        let name = CString::new(name.as_bytes())
            .map_err(|_| String::from("a protected receipt archive name is invalid"))?;
        let archive = read_regular_file(directory.as_raw_fd(), &name, expected_owner_uid)?;
        if archive.content_identity != receipt_archive_identity {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(&archive.bytes)
            .map_err(|_| String::from("the protected receipt archive is invalid"))?;
        if value
            .pointer("/receipt/crossing/authority/archive_evidence/transaction/identity")
            .and_then(serde_json::Value::as_str)
            != Some(crossing_transaction_identity)
        {
            return Err(String::from(
                "the protected receipt archive transaction identity is invalid",
            ));
        }
        let snapshot_ref = value
            .pointer("/receipt/contract_snapshot_ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                String::from("the protected receipt archive omits its contract snapshot")
            })?;
        let snapshot_identity = value
            .pointer("/receipt/contract_snapshot_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                String::from("the protected receipt archive omits its contract snapshot identity")
            })?;
        let snapshot_name = contract_snapshot_name(repository_fd, snapshot_ref)?;
        let snapshot = read_contract_snapshot(repository_fd, expected_owner_uid, &snapshot_name)?;
        if snapshot.content_identity != snapshot_identity {
            return Err(String::from(
                "the protected contract snapshot identity is invalid",
            ));
        }
        matches.push((name, archive, snapshot));
    }
    if matches.len() != 1 {
        return Err(String::from(
            "the exact protected receipt archive is unavailable or ambiguous",
        ));
    }
    let (archive_name, archive, contract_snapshot) = matches.pop().expect("one protected archive");
    let archive_file_name = archive_name
        .to_str()
        .map_err(|_| String::from("the protected receipt archive name is invalid"))?;
    let sidecar_file_name = format!(
        "{}.launcher-finalization",
        archive_file_name
            .strip_suffix(".json")
            .ok_or_else(|| String::from("the protected receipt archive name is invalid"))?
    );
    let sidecar_name = CString::new(sidecar_file_name.as_str())
        .map_err(|_| String::from("the launcher finalization sidecar name is invalid"))?;
    Ok(ArchiveAttachmentTarget {
        directory,
        archive_name,
        sidecar_name,
        sidecar_file_name,
        receipt_archive_identity: receipt_archive_identity.into(),
        expected_owner_uid,
        archive,
        contract_snapshot,
    })
}

pub(crate) fn persist_sidecar(
    target: &ArchiveAttachmentTarget,
    sidecar: &LauncherFinalizationArchiveSidecarV1,
) -> Result<(), String> {
    let archive = read_regular_file(
        target.directory.as_raw_fd(),
        &target.archive_name,
        target.expected_owner_uid,
    )?;
    if archive.content_identity != target.receipt_archive_identity || archive != target.archive {
        return Err(String::from(
            "the protected receipt archive changed before sidecar publication",
        ));
    }
    let bytes = serde_jcs::to_vec(sidecar)
        .map_err(|_| String::from("the launcher finalization sidecar cannot be encoded"))?;
    if existing_file_matches(&target.directory, &target.sidecar_name, &bytes)? {
        return Ok(());
    }
    let mut suffix = [0_u8; 16];
    getrandom::getrandom(&mut suffix)
        .map_err(|_| String::from("the launcher finalization temporary name is unavailable"))?;
    let temporary_name = CString::new(format!(
        ".{}.{}.tmp",
        target.sidecar_file_name,
        suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
    .map_err(|_| String::from("the launcher finalization temporary name is invalid"))?;
    let descriptor = unsafe {
        libc::openat(
            target.directory.as_raw_fd(),
            temporary_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(String::from(
            "the launcher finalization temporary sidecar cannot be created",
        ));
    }
    let mut temporary = unsafe { File::from_raw_fd(descriptor) };
    let mut published = false;
    let result = (|| {
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.sync_all())
            .map_err(|_| String::from("the launcher finalization sidecar cannot be persisted"))?;
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                target.directory.as_raw_fd(),
                temporary_name.as_ptr(),
                target.directory.as_raw_fd(),
                target.sidecar_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
                && existing_file_matches(&target.directory, &target.sidecar_name, &bytes)?
            {
                return Ok(());
            }
            return Err(String::from(
                "the launcher finalization sidecar cannot be published",
            ));
        }
        published = true;
        target
            .directory
            .sync_all()
            .map_err(|_| String::from("the launcher finalization sidecar cannot be persisted"))
    })();
    if !published {
        unsafe {
            libc::unlinkat(target.directory.as_raw_fd(), temporary_name.as_ptr(), 0);
        }
    }
    result
}

fn open_receipt_directory(repository_fd: RawFd, expected_owner_uid: u32) -> Result<File, String> {
    let ota_descriptor = unsafe {
        libc::openat(
            repository_fd,
            OTA_DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if ota_descriptor < 0 {
        return Err(String::from(
            "the protected receipt archive directory is unavailable",
        ));
    }
    let ota_directory = unsafe { File::from_raw_fd(ota_descriptor) };
    verify_private_directory(&ota_directory, expected_owner_uid)?;
    let descriptor = unsafe {
        libc::openat(
            ota_directory.as_raw_fd(),
            RECEIPT_DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(String::from(
            "the protected receipt archive directory is unavailable",
        ));
    }
    let receipts = unsafe { File::from_raw_fd(descriptor) };
    verify_private_directory(&receipts, expected_owner_uid)?;
    Ok(receipts)
}

fn verify_private_directory(directory: &File, expected_owner_uid: u32) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|_| String::from("the protected receipt archive directory is unreadable"))?;
    if !metadata.is_dir()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(String::from(
            "the protected receipt archive directory has unsafe metadata",
        ));
    }
    Ok(())
}

fn read_regular_file(
    directory_fd: RawFd,
    name: &CStr,
    expected_owner_uid: u32,
) -> Result<FrozenAttachmentObject, String> {
    let descriptor = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(String::from("a protected receipt archive is unreadable"));
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|_| String::from("a protected receipt archive is unreadable"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_ARCHIVE_BYTES
    {
        return Err(String::from(
            "a protected receipt archive has unsafe metadata",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| String::from("a protected receipt archive is unreadable"))?;
    let content_identity = format!("sha256:{:x}", Sha256::digest(&bytes));
    Ok(FrozenAttachmentObject {
        bytes,
        content_identity,
        owner_uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
    })
}

fn contract_snapshot_name(repository_fd: RawFd, snapshot_ref: &str) -> Result<CString, String> {
    let mut path = Path::new(snapshot_ref);
    let absolute_reference;
    if path.is_absolute() {
        let repository = fs::read_link(format!("/proc/self/fd/{repository_fd}"))
            .map_err(|_| String::from("the protected contract snapshot reference is invalid"))?;
        let expected_prefix = repository.join(".ota/contracts");
        let Some(name) = path
            .strip_prefix(&expected_prefix)
            .ok()
            .and_then(|relative| {
                let mut components = relative.components();
                match (components.next(), components.next()) {
                    (Some(std::path::Component::Normal(name)), None) => Some(name),
                    _ => None,
                }
            })
        else {
            return Err(String::from(
                "the protected contract snapshot reference is invalid",
            ));
        };
        absolute_reference = PathBuf::from(".ota/contracts").join(name);
        path = absolute_reference.as_path();
    }
    let mut components = path.components().peekable();
    if matches!(components.peek(), Some(std::path::Component::CurDir)) {
        components.next();
    }
    let valid_prefix = matches!(components.next(), Some(std::path::Component::Normal(value)) if value == ".ota")
        && matches!(components.next(), Some(std::path::Component::Normal(value)) if value == "contracts");
    let name = match (valid_prefix, components.next(), components.next()) {
        (true, Some(std::path::Component::Normal(name)), None)
            if Path::new(name).extension().and_then(|value| value.to_str()) == Some("json") =>
        {
            name
        }
        _ => {
            return Err(String::from(
                "the protected contract snapshot reference is invalid",
            ));
        }
    };
    CString::new(name.as_bytes())
        .map_err(|_| String::from("the protected contract snapshot reference is invalid"))
}

fn read_contract_snapshot(
    repository_fd: RawFd,
    expected_owner_uid: u32,
    name: &CStr,
) -> Result<FrozenAttachmentObject, String> {
    let ota_descriptor = unsafe {
        libc::openat(
            repository_fd,
            OTA_DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if ota_descriptor < 0 {
        return Err(String::from(
            "the protected contract snapshot is unavailable",
        ));
    }
    let ota = unsafe { File::from_raw_fd(ota_descriptor) };
    verify_private_directory(&ota, expected_owner_uid)?;
    let contracts_descriptor = unsafe {
        libc::openat(
            ota.as_raw_fd(),
            CONTRACT_DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if contracts_descriptor < 0 {
        return Err(String::from(
            "the protected contract snapshot is unavailable",
        ));
    }
    let contracts = unsafe { File::from_raw_fd(contracts_descriptor) };
    verify_private_directory(&contracts, expected_owner_uid)?;
    read_regular_file(contracts.as_raw_fd(), name, expected_owner_uid)
        .map_err(|_| String::from("the protected contract snapshot is unavailable"))
}

fn existing_file_matches(directory: &File, name: &CStr, expected: &[u8]) -> Result<bool, String> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => Ok(false),
            _ => Err(String::from(
                "the existing launcher finalization sidecar is unsafe or unreadable",
            )),
        };
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|_| String::from("the existing launcher finalization sidecar is unreadable"))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != expected.len() as u64
    {
        return Err(String::from(
            "the existing launcher finalization sidecar has unsafe metadata",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| String::from("the existing launcher finalization sidecar is unreadable"))?;
    if bytes != expected {
        return Err(String::from(
            "the existing launcher finalization sidecar does not match this execution",
        ));
    }
    file.sync_all()
        .and_then(|()| directory.sync_all())
        .map_err(|_| String::from("the existing launcher finalization sidecar is not durable"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use ota_authority_protocol::{
        LAUNCHER_EXECUTION_COMPLETION, LauncherExecutionCompletionV1,
        LauncherExecutionFinalizationV1, LauncherExecutionOutcomeV1,
        LauncherFinalizationArchiveSidecarV1, SignedLauncherExecutionFinalizationV1,
        SignedLauncherFinalizationArchiveV1, launcher_execution_completion_v1_identity,
        launcher_execution_finalization_v1_identity,
        launcher_finalization_archive_sidecar_v1_identity,
        signed_launcher_execution_finalization_v1_identity,
        signed_launcher_finalization_archive_v1_identity,
    };
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn fixture() -> (
        tempfile::TempDir,
        File,
        String,
        String,
        LauncherFinalizationArchiveSidecarV1,
    ) {
        let root = tempdir().expect("repository");
        let receipts = root.path().join(".ota/receipts");
        let contracts = root.path().join(".ota/contracts");
        fs::create_dir_all(&receipts).expect("receipts");
        fs::create_dir_all(&contracts).expect("contracts");
        fs::set_permissions(root.path().join(".ota"), fs::Permissions::from_mode(0o700))
            .expect("ota permissions");
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700))
            .expect("receipt permissions");
        fs::set_permissions(&contracts, fs::Permissions::from_mode(0o700))
            .expect("contract permissions");
        let crossing = identity('4');
        let snapshot_bytes = br#"{"schema_version":1}"#;
        let snapshot_identity = format!("sha256:{:x}", Sha256::digest(snapshot_bytes));
        let snapshot_name = format!(
            "sha256-{}.json",
            snapshot_identity.trim_start_matches("sha256:")
        );
        let snapshot_path = contracts.join(&snapshot_name);
        fs::write(&snapshot_path, snapshot_bytes).expect("snapshot");
        fs::set_permissions(&snapshot_path, fs::Permissions::from_mode(0o600))
            .expect("snapshot permissions");
        let archive_path = receipts.join("repo-receipt-1.json");
        let archive = serde_json::json!({
            "receipt": {
                "contract_snapshot_hash": snapshot_identity,
                "contract_snapshot_ref": format!("./.ota/contracts/{snapshot_name}"),
                "crossing": { "authority": { "archive_evidence": {
                    "transaction": { "identity": crossing }
                }}}
            }
        });
        let bytes = serde_json::to_vec(&archive).expect("archive bytes");
        fs::write(&archive_path, &bytes).expect("archive");
        fs::set_permissions(&archive_path, fs::Permissions::from_mode(0o600))
            .expect("archive permissions");
        let archive_identity = format!("sha256:{:x}", Sha256::digest(&bytes));
        let mut completion = LauncherExecutionCompletionV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_EXECUTION_COMPLETION.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            lease_consumption_admission_identity: identity('1'),
            work_unit_identity: identity('2'),
            crossing_transaction_id: String::from("transaction-1"),
            pending_crossing_transaction_identity: identity('3'),
            crossing_transaction_identity: identity('4'),
            receipt_archive_identity: Some(archive_identity.clone()),
            outcome: LauncherExecutionOutcomeV1::Completed,
            exit_code: Some(0),
            receipt_status: String::from("passed"),
        };
        completion.identity =
            launcher_execution_completion_v1_identity(&completion).expect("completion");
        let mut finalization = LauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            completion,
            child_identity: identity('5'),
            scope_identity: identity('6'),
            child_exit_posture: None,
            observed_exit_code: Some(0),
            child_reaped: true,
            child_absent: None,
            scope_removed: true,
            cgroup_empty_or_absent: true,
            active_slot_removed: true,
        };
        finalization.identity =
            launcher_execution_finalization_v1_identity(&finalization).expect("finalization");
        let mut signed_finalization = SignedLauncherExecutionFinalizationV1 {
            schema_version: 1,
            identity: String::new(),
            finalization,
            producer_binding_identity: identity('7'),
            issued_at: String::from("2026-08-13T12:00:00Z"),
            key_id: String::from("attestor-1"),
            algorithm: String::from("ed25519"),
            signature: String::from("signature"),
        };
        signed_finalization.identity =
            signed_launcher_execution_finalization_v1_identity(&signed_finalization)
                .expect("signed finalization");
        let mut signed_archive = SignedLauncherFinalizationArchiveV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization_identity: signed_finalization.identity.clone(),
            receipt_archive_identity: archive_identity.clone(),
            crossing_transaction_identity: identity('4'),
            producer_binding_identity: identity('7'),
            issued_at: String::from("2026-08-13T12:00:01Z"),
            key_id: String::from("attestor-1"),
            algorithm: String::from("ed25519"),
            signature: String::from("archive-signature"),
        };
        signed_archive.identity = signed_launcher_finalization_archive_v1_identity(&signed_archive)
            .expect("signed archive");
        let mut sidecar = LauncherFinalizationArchiveSidecarV1 {
            schema_version: 1,
            identity: String::new(),
            signed_finalization,
            signed_archive,
        };
        sidecar.identity =
            launcher_finalization_archive_sidecar_v1_identity(&sidecar).expect("sidecar");
        let repository = File::open(root.path()).expect("repository descriptor");
        (root, repository, archive_identity, identity('4'), sidecar)
    }

    #[test]
    fn exact_archive_is_located_and_sidecar_is_atomic_and_idempotent() {
        let (root, repository, archive, crossing, sidecar) = fixture();
        let target = locate_archive(
            repository.as_raw_fd(),
            unsafe { libc::geteuid() },
            &archive,
            &crossing,
        )
        .expect("exact archive");
        persist_sidecar(&target, &sidecar).expect("sidecar publication");
        persist_sidecar(&target, &sidecar).expect("idempotent sidecar publication");
        let path = root
            .path()
            .join(".ota/receipts")
            .join(target.sidecar_file_name);
        assert_eq!(
            serde_json::from_slice::<LauncherFinalizationArchiveSidecarV1>(
                &fs::read(path).expect("sidecar bytes")
            )
            .expect("sidecar JSON"),
            sidecar
        );
    }

    #[test]
    fn contract_snapshot_reference_accepts_otas_display_form_without_widening() {
        let name = "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json";
        let repository = File::open(".").expect("repository descriptor");
        assert!(
            contract_snapshot_name(repository.as_raw_fd(), &format!(".ota/contracts/{name}"))
                .is_ok()
        );
        assert!(
            contract_snapshot_name(repository.as_raw_fd(), &format!("./.ota/contracts/{name}"))
                .is_ok()
        );
        assert!(
            contract_snapshot_name(
                repository.as_raw_fd(),
                &std::env::current_dir()
                    .expect("current directory")
                    .join(".ota/contracts")
                    .join(name)
                    .to_string_lossy(),
            )
            .is_ok()
        );
        for reference in [
            format!("../.ota/contracts/{name}"),
            format!("/.ota/contracts/{name}"),
            format!(".ota/contracts/nested/{name}"),
            format!(".ota/receipts/{name}"),
        ] {
            assert!(
                contract_snapshot_name(repository.as_raw_fd(), &reference).is_err(),
                "{reference}"
            );
        }
    }

    #[test]
    fn archive_identity_transaction_and_sidecar_aliases_refuse() {
        let (root, repository, archive, crossing, sidecar) = fixture();
        let owner = unsafe { libc::geteuid() };
        assert!(
            locate_archive(
                repository.as_raw_fd(),
                owner.saturating_add(1),
                &archive,
                &crossing,
            )
            .is_err()
        );
        assert!(locate_archive(repository.as_raw_fd(), owner, &identity('a'), &crossing).is_err());
        assert!(locate_archive(repository.as_raw_fd(), owner, &archive, &identity('b')).is_err());
        let target = locate_archive(repository.as_raw_fd(), owner, &archive, &crossing)
            .expect("exact archive");
        let sidecar_path = root
            .path()
            .join(".ota/receipts")
            .join(&target.sidecar_file_name);
        let alias_target = root.path().join("alias-target");
        fs::write(&alias_target, b"alias").expect("alias target");
        symlink(&alias_target, &sidecar_path).expect("sidecar symlink");
        assert!(persist_sidecar(&target, &sidecar).is_err());
        fs::remove_file(&sidecar_path).expect("remove symlink");
        fs::hard_link(&alias_target, &sidecar_path).expect("sidecar hardlink");
        assert!(persist_sidecar(&target, &sidecar).is_err());
    }

    #[test]
    fn writable_or_traversable_receipt_directories_refuse() {
        let (root, repository, archive, crossing, _) = fixture();
        let owner = unsafe { libc::geteuid() };
        fs::set_permissions(
            root.path().join(".ota/receipts"),
            fs::Permissions::from_mode(0o750),
        )
        .expect("unsafe receipt permissions");
        assert!(locate_archive(repository.as_raw_fd(), owner, &archive, &crossing).is_err());

        fs::set_permissions(
            root.path().join(".ota/receipts"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore receipt permissions");
        fs::set_permissions(root.path().join(".ota"), fs::Permissions::from_mode(0o770))
            .expect("unsafe ota permissions");
        assert!(locate_archive(repository.as_raw_fd(), owner, &archive, &crossing).is_err());
    }

    #[test]
    fn missing_changed_or_aliased_contract_snapshot_refuses() {
        let (root, repository, archive, crossing, _) = fixture();
        let owner = unsafe { libc::geteuid() };
        let snapshot = fs::read_dir(root.path().join(".ota/contracts"))
            .expect("contracts")
            .next()
            .expect("snapshot entry")
            .expect("snapshot")
            .path();
        fs::write(&snapshot, br#"{"schema_version":2}"#).expect("changed snapshot");
        assert!(locate_archive(repository.as_raw_fd(), owner, &archive, &crossing).is_err());

        fs::remove_file(&snapshot).expect("remove snapshot");
        let alias_target = root.path().join("snapshot-alias-target");
        fs::write(&alias_target, br#"{"schema_version":1}"#).expect("alias target");
        symlink(&alias_target, &snapshot).expect("snapshot symlink");
        assert!(locate_archive(repository.as_raw_fd(), owner, &archive, &crossing).is_err());
    }
}
