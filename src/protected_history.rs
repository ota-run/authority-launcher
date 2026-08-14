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

//! Launcher-owned protected archive storage and repository-to-authority mapping.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ota_authority_protocol::{
    LauncherFinalizationArchiveSidecarV1, LauncherWorkingDirectoryV1,
    launcher_finalization_archive_sidecar_v1_identity, launcher_working_directory_identity,
    message_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::archive_attachment::{ArchiveAttachmentTarget, FrozenAttachmentObject};
use crate::config::{
    open_protected_executable, open_protected_file, sha256_file_identity,
    verify_protected_directory,
};
use crate::finalization_journal::FinalizationJournalV1;

pub(crate) const HISTORY_BINDING_PATH: &str = "/etc/ota/authority-history.json";
pub(crate) const HISTORY_SOCKET_PATH: &str = "/run/ota/authority-history.sock";
pub(crate) const HISTORY_BLOB_ROOT: &str = "/var/lib/ota/authority-launcher/history/blobs";
pub(crate) const HISTORY_CATALOG_ROOT: &str = "/var/lib/ota/authority-launcher/history/catalog";
const HISTORY_BINDING_IDENTITY_DOMAIN_V1: &[u8] = b"ota.authority-launcher.history-binding.v1\0";
const HISTORY_REPOSITORY_MAPPING_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-repository-mapping.v1\0";
const HISTORY_BLOB_IDENTITY_DOMAIN_V1: &[u8] = b"ota.authority-launcher.history-blob.v1\0";
const HISTORY_CATALOG_ENTRY_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-catalog-entry.v1\0";
const MAX_BINDING_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryBindingV1 {
    pub(crate) schema_version: u32,
    pub(crate) identity: String,
    pub(crate) protocol_profile: String,
    pub(crate) socket_path: PathBuf,
    pub(crate) socket_group_gid: u32,
    pub(crate) installation_manifest_identity: String,
    pub(crate) installed_client_path: PathBuf,
    pub(crate) installed_client_identity: String,
    pub(crate) operator_uid: u32,
    pub(crate) operator_gid: u32,
    pub(crate) operator_profile_identity: String,
    pub(crate) service_unit_identity: String,
    pub(crate) socket_unit_identity: String,
    pub(crate) blob_root: PathBuf,
    pub(crate) catalog_root: PathBuf,
    pub(crate) maximum_response_bytes: u64,
    pub(crate) maximum_entry_count: u32,
    pub(crate) mappings: Vec<ProtectedHistoryRepositoryMappingV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryRepositoryMappingV1 {
    pub(crate) schema_version: u32,
    pub(crate) identity: String,
    pub(crate) repository_binding_identity: String,
    pub(crate) catalog_namespace_identity: String,
    pub(crate) authority_id: String,
    pub(crate) working_directory: LauncherWorkingDirectoryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryFileMetadataV1 {
    pub(crate) owner_uid: u32,
    pub(crate) mode: u32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) link_count: u64,
    pub(crate) size: u64,
    pub(crate) content_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryBlobV1 {
    pub(crate) schema_version: u32,
    pub(crate) identity: String,
    pub(crate) content_identity: String,
    pub(crate) size: u64,
    pub(crate) metadata: ProtectedHistoryFileMetadataV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryCatalogEntryV1 {
    pub(crate) schema_version: u32,
    pub(crate) identity: String,
    pub(crate) authority_id: String,
    pub(crate) repository_binding_identity: String,
    pub(crate) catalog_namespace_identity: String,
    pub(crate) repository_mapping_identity: String,
    pub(crate) operator_profile_identity: String,
    pub(crate) working_directory: LauncherWorkingDirectoryV1,
    pub(crate) launcher_request_identity: String,
    pub(crate) work_unit_identity: String,
    pub(crate) crossing_transaction_identity: String,
    pub(crate) receipt_archive_identity: String,
    pub(crate) contract_snapshot_identity: String,
    pub(crate) sidecar_identity: String,
    pub(crate) signed_finalization_identity: String,
    pub(crate) signed_archive_identity: String,
    pub(crate) finalization_journal_identity: String,
    pub(crate) archive_source: ProtectedHistoryFileMetadataV1,
    pub(crate) contract_snapshot_source: ProtectedHistoryFileMetadataV1,
    pub(crate) archive_blob: ProtectedHistoryBlobV1,
    pub(crate) contract_snapshot_blob: ProtectedHistoryBlobV1,
    pub(crate) sidecar_blob: ProtectedHistoryBlobV1,
    pub(crate) creation_posture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedHistoryAttachmentV1 {
    pub(crate) schema_version: u32,
    pub(crate) catalog_identity: String,
    pub(crate) repository_binding_identity: String,
    pub(crate) catalog_namespace_identity: String,
    pub(crate) archive_blob_identity: String,
    pub(crate) contract_snapshot_blob_identity: String,
    pub(crate) sidecar_blob_identity: String,
    pub(crate) finalization_journal_identity: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ProtectedHistoryError {
    #[error("the protected history binding is unavailable")]
    BindingUnavailable,
    #[error("the protected history binding is invalid")]
    BindingInvalid,
    #[error("the protected repository history mapping is unavailable or ambiguous")]
    MappingUnavailable,
    #[error("the protected history store is unavailable or unsafe")]
    StoreUnavailable,
    #[error("the protected history object is invalid")]
    ObjectInvalid,
    #[error("the protected history object could not be persisted")]
    PersistenceFailed,
}

pub(crate) fn load_protected_history_binding()
-> Result<ProtectedHistoryBindingV1, ProtectedHistoryError> {
    load_protected_history_binding_at(Path::new(HISTORY_BINDING_PATH), 0, Path::new("/"))
}

fn load_protected_history_binding_at(
    path: &Path,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<ProtectedHistoryBindingV1, ProtectedHistoryError> {
    let mut file = open_protected_file(path, expected_owner_uid, trusted_root)
        .map_err(|_| ProtectedHistoryError::BindingUnavailable)?;
    if file
        .metadata()
        .map_err(|_| ProtectedHistoryError::BindingUnavailable)?
        .len()
        > MAX_BINDING_BYTES
    {
        return Err(ProtectedHistoryError::BindingInvalid);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| ProtectedHistoryError::BindingUnavailable)?;
    let binding: ProtectedHistoryBindingV1 =
        serde_json::from_slice(&bytes).map_err(|_| ProtectedHistoryError::BindingInvalid)?;
    validate_binding(&binding, expected_owner_uid, trusted_root)?;
    Ok(binding)
}

fn validate_binding(
    binding: &ProtectedHistoryBindingV1,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<(), ProtectedHistoryError> {
    if binding.schema_version != 1
        || binding.protocol_profile != ota_authority_protocol::SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1
        || binding.socket_path != Path::new(HISTORY_SOCKET_PATH)
        || binding.socket_group_gid == 0
        || !is_sha256(&binding.installation_manifest_identity)
        || binding.operator_uid == 0
        || binding.operator_gid != binding.socket_group_gid
        || !is_sha256(&binding.installed_client_identity)
        || !is_sha256(&binding.operator_profile_identity)
        || !is_sha256(&binding.service_unit_identity)
        || !is_sha256(&binding.socket_unit_identity)
        || !has_canonical_storage_roots(binding)
        || binding.maximum_response_bytes == 0
        || binding.maximum_response_bytes > ota_authority_protocol::MAX_HISTORY_RESPONSE_BYTES_V1
        || binding.maximum_entry_count == 0
        || usize::try_from(binding.maximum_entry_count).map_or(true, |count| {
            count > ota_authority_protocol::MAX_HISTORY_ENTRY_COUNT_V1
        })
        || binding.mappings.is_empty()
        || protected_history_binding_identity(binding)? != binding.identity
    {
        eprintln!("ota-authority-launcher: protected history binding failed stage=shape");
        return Err(ProtectedHistoryError::BindingInvalid);
    }
    verify_protected_directory(&binding.blob_root, expected_owner_uid, trusted_root)
        .and_then(|()| {
            verify_protected_directory(&binding.catalog_root, expected_owner_uid, trusted_root)
        })
        .map_err(|_| {
            eprintln!("ota-authority-launcher: protected history binding failed stage=storage");
            ProtectedHistoryError::StoreUnavailable
        })?;
    let mut client = open_protected_executable(
        &binding.installed_client_path,
        expected_owner_uid,
        trusted_root,
    )
    .map_err(|_| {
        eprintln!("ota-authority-launcher: protected history binding failed stage=client_open");
        ProtectedHistoryError::BindingInvalid
    })?;
    if sha256_file_identity(&mut client).map_err(|_| ProtectedHistoryError::BindingInvalid)?
        != binding.installed_client_identity
    {
        eprintln!("ota-authority-launcher: protected history binding failed stage=client_identity");
        return Err(ProtectedHistoryError::BindingInvalid);
    }
    let launcher_executable =
        std::env::current_exe().map_err(|_| ProtectedHistoryError::BindingInvalid)?;
    crate::installation_manifest::verify_protected_history_installation(
        binding.installation_manifest_identity.as_str(),
        launcher_executable.as_path(),
        Path::new(HISTORY_BINDING_PATH),
        binding.installed_client_path.as_path(),
        binding.installed_client_identity.as_str(),
        binding.service_unit_identity.as_str(),
        binding.socket_unit_identity.as_str(),
    )
    .map_err(|_| {
        eprintln!("ota-authority-launcher: protected history binding failed stage=installation");
        ProtectedHistoryError::BindingInvalid
    })?;
    let mut mapping_ids = std::collections::BTreeSet::new();
    let mut repository_ids = std::collections::BTreeSet::new();
    let mut namespaces = std::collections::BTreeSet::new();
    for mapping in &binding.mappings {
        if mapping.schema_version != 1
            || !is_label(&mapping.authority_id)
            || !is_sha256(&mapping.repository_binding_identity)
            || !is_sha256(&mapping.catalog_namespace_identity)
            || launcher_working_directory_identity(&mapping.working_directory)
                .ok()
                .as_deref()
                != Some(mapping.working_directory.identity.as_str())
            || protected_history_repository_mapping_identity(mapping)? != mapping.identity
            || !mapping_ids.insert(mapping.identity.clone())
            || !repository_ids.insert(mapping.repository_binding_identity.clone())
            || !namespaces.insert(mapping.catalog_namespace_identity.clone())
        {
            eprintln!("ota-authority-launcher: protected history binding failed stage=mapping");
            return Err(ProtectedHistoryError::BindingInvalid);
        }
        let namespace = namespace_path(&binding.catalog_root, &mapping.catalog_namespace_identity)?;
        verify_protected_directory(&namespace, expected_owner_uid, trusted_root).map_err(|_| {
            eprintln!("ota-authority-launcher: protected history binding failed stage=namespace");
            ProtectedHistoryError::StoreUnavailable
        })?;
    }
    Ok(())
}

fn has_canonical_storage_roots(binding: &ProtectedHistoryBindingV1) -> bool {
    binding.blob_root == Path::new(HISTORY_BLOB_ROOT)
        && binding.catalog_root == Path::new(HISTORY_CATALOG_ROOT)
}

pub(crate) fn protected_history_binding_identity(
    binding: &ProtectedHistoryBindingV1,
) -> Result<String, ProtectedHistoryError> {
    let mut canonical = binding.clone();
    canonical.identity.clear();
    message_identity(HISTORY_BINDING_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| ProtectedHistoryError::BindingInvalid)
}

pub(crate) fn protected_history_repository_mapping_identity(
    mapping: &ProtectedHistoryRepositoryMappingV1,
) -> Result<String, ProtectedHistoryError> {
    let mut canonical = mapping.clone();
    canonical.identity.clear();
    message_identity(HISTORY_REPOSITORY_MAPPING_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| ProtectedHistoryError::BindingInvalid)
}

pub(crate) fn select_mapping<'a>(
    binding: &'a ProtectedHistoryBindingV1,
    authority_id: &str,
    working_directory: &LauncherWorkingDirectoryV1,
) -> Result<&'a ProtectedHistoryRepositoryMappingV1, ProtectedHistoryError> {
    let matches = binding
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.authority_id == authority_id && mapping.working_directory == *working_directory
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [mapping] => Ok(*mapping),
        _ => Err(ProtectedHistoryError::MappingUnavailable),
    }
}

pub(crate) fn attach_protected_history(
    binding: &ProtectedHistoryBindingV1,
    target: &ArchiveAttachmentTarget,
    sidecar: &LauncherFinalizationArchiveSidecarV1,
    journal: &FinalizationJournalV1,
) -> Result<ProtectedHistoryAttachmentV1, ProtectedHistoryError> {
    let request = journal
        .archive_request
        .as_ref()
        .ok_or(ProtectedHistoryError::ObjectInvalid)?;
    let mapping = select_mapping(binding, &request.authority_id, &journal.working_directory)?;
    if launcher_finalization_archive_sidecar_v1_identity(sidecar)
        .ok()
        .as_deref()
        != Some(sidecar.identity.as_str())
        || sidecar.signed_archive.receipt_archive_identity != target.archive.content_identity
    {
        return Err(ProtectedHistoryError::ObjectInvalid);
    }
    let sidecar_bytes =
        serde_jcs::to_vec(sidecar).map_err(|_| ProtectedHistoryError::ObjectInvalid)?;
    let archive_blob = persist_blob(&binding.blob_root, &target.archive.bytes, 0)?;
    let contract_snapshot_blob =
        persist_blob(&binding.blob_root, &target.contract_snapshot.bytes, 0)?;
    let sidecar_blob = persist_blob(&binding.blob_root, &sidecar_bytes, 0)?;
    let mut entry = ProtectedHistoryCatalogEntryV1 {
        schema_version: 1,
        identity: String::new(),
        authority_id: mapping.authority_id.clone(),
        repository_binding_identity: mapping.repository_binding_identity.clone(),
        catalog_namespace_identity: mapping.catalog_namespace_identity.clone(),
        repository_mapping_identity: mapping.identity.clone(),
        operator_profile_identity: binding.operator_profile_identity.clone(),
        working_directory: mapping.working_directory.clone(),
        launcher_request_identity: journal.launcher_request_identity.clone(),
        work_unit_identity: journal.finalization.completion.work_unit_identity.clone(),
        crossing_transaction_identity: journal
            .finalization
            .completion
            .crossing_transaction_identity
            .clone(),
        receipt_archive_identity: target.archive.content_identity.clone(),
        contract_snapshot_identity: target.contract_snapshot.content_identity.clone(),
        sidecar_identity: sidecar.identity.clone(),
        signed_finalization_identity: sidecar.signed_finalization.identity.clone(),
        signed_archive_identity: sidecar.signed_archive.identity.clone(),
        finalization_journal_identity: journal.protected_history_attachment.as_ref().map_or_else(
            || journal.identity.clone(),
            |attachment| attachment.finalization_journal_identity.clone(),
        ),
        archive_source: source_metadata(&target.archive),
        contract_snapshot_source: source_metadata(&target.contract_snapshot),
        archive_blob,
        contract_snapshot_blob,
        sidecar_blob,
        creation_posture: String::from("frozen_before_terminal_acknowledgement"),
    };
    entry.identity = catalog_entry_identity(&entry)?;
    persist_catalog_entry(binding, mapping, &entry, 0)?;
    Ok(ProtectedHistoryAttachmentV1 {
        schema_version: 1,
        catalog_identity: entry.identity,
        repository_binding_identity: entry.repository_binding_identity,
        catalog_namespace_identity: entry.catalog_namespace_identity,
        archive_blob_identity: entry.archive_blob.identity,
        contract_snapshot_blob_identity: entry.contract_snapshot_blob.identity,
        sidecar_blob_identity: entry.sidecar_blob.identity,
        finalization_journal_identity: entry.finalization_journal_identity,
    })
}

fn source_metadata(source: &FrozenAttachmentObject) -> ProtectedHistoryFileMetadataV1 {
    ProtectedHistoryFileMetadataV1 {
        owner_uid: source.owner_uid,
        mode: source.mode,
        device: source.device,
        inode: source.inode,
        link_count: source.link_count,
        size: source.bytes.len() as u64,
        content_identity: source.content_identity.clone(),
    }
}

fn persist_blob(
    root: &Path,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<ProtectedHistoryBlobV1, ProtectedHistoryError> {
    let content_identity = format!("sha256:{:x}", Sha256::digest(bytes));
    let name = identity_file_name(&content_identity)?;
    persist_exact_file(root, name, bytes, expected_owner_uid)?;
    let metadata = verified_file_metadata(root, name, expected_owner_uid, Some(&content_identity))?;
    let mut blob = ProtectedHistoryBlobV1 {
        schema_version: 1,
        identity: String::new(),
        content_identity,
        size: bytes.len() as u64,
        metadata,
    };
    blob.identity = blob_identity(&blob)?;
    Ok(blob)
}

fn persist_catalog_entry(
    binding: &ProtectedHistoryBindingV1,
    mapping: &ProtectedHistoryRepositoryMappingV1,
    entry: &ProtectedHistoryCatalogEntryV1,
    expected_owner_uid: u32,
) -> Result<(), ProtectedHistoryError> {
    let namespace = namespace_path(&binding.catalog_root, &mapping.catalog_namespace_identity)?;
    let name = format!("{}.json", identity_file_name(&entry.identity)?);
    let bytes = serde_jcs::to_vec(entry).map_err(|_| ProtectedHistoryError::ObjectInvalid)?;
    persist_exact_file(&namespace, &name, &bytes, expected_owner_uid)
}

pub(crate) fn load_catalog_entries(
    binding: &ProtectedHistoryBindingV1,
    mapping: &ProtectedHistoryRepositoryMappingV1,
) -> Result<Vec<ProtectedHistoryCatalogEntryV1>, ProtectedHistoryError> {
    let namespace = namespace_path(&binding.catalog_root, &mapping.catalog_namespace_identity)?;
    let mut entries = Vec::new();
    for name in list_directory_names(&namespace, 0)? {
        if is_internal_temporary_name(&name) {
            // A crash before rename can leave a same-directory staging file. It is not catalog
            // truth, but it must still be a protected regular file before being ignored so an
            // alias or foreign object cannot hide behind the recovery namespace.
            read_exact_file(&namespace, &name, 0, None)?;
            continue;
        }
        if !name.ends_with(".json") {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=name");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        let identity_name = name
            .strip_suffix(".json")
            .ok_or(ProtectedHistoryError::ObjectInvalid)?;
        identity_file_name(&format!("sha256:{identity_name}")).inspect_err(|_| {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=name");
        })?;
        let bytes = read_exact_file(&namespace, &name, 0, None)
            .inspect_err(|_| {
                eprintln!("ota-authority-launcher: protected history catalog failed stage=file");
            })?
            .0;
        let entry: ProtectedHistoryCatalogEntryV1 =
            serde_json::from_slice(&bytes).map_err(|_| {
                eprintln!("ota-authority-launcher: protected history catalog failed stage=decode");
                ProtectedHistoryError::ObjectInvalid
            })?;
        if catalog_entry_identity(&entry)? != entry.identity {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=identity");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        if entry.repository_mapping_identity != mapping.identity
            || entry.repository_binding_identity != mapping.repository_binding_identity
            || entry.catalog_namespace_identity != mapping.catalog_namespace_identity
            || entry.operator_profile_identity != binding.operator_profile_identity
            || entry.authority_id != mapping.authority_id
            || entry.working_directory != mapping.working_directory
        {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=mapping");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        if entry.receipt_archive_identity != entry.archive_blob.content_identity
            || entry.receipt_archive_identity != entry.archive_source.content_identity
            || entry.contract_snapshot_identity != entry.contract_snapshot_blob.content_identity
            || entry.contract_snapshot_identity != entry.contract_snapshot_source.content_identity
        {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=objects");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        if !is_sha256(&entry.launcher_request_identity)
            || !is_sha256(&entry.work_unit_identity)
            || !is_sha256(&entry.crossing_transaction_identity)
            || !is_sha256(&entry.sidecar_identity)
            || !is_sha256(&entry.signed_finalization_identity)
            || !is_sha256(&entry.signed_archive_identity)
            || !is_sha256(&entry.finalization_journal_identity)
        {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=identities");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        if entry.creation_posture != "frozen_before_terminal_acknowledgement" {
            eprintln!("ota-authority-launcher: protected history catalog failed stage=posture");
            return Err(ProtectedHistoryError::ObjectInvalid);
        }
        entries.push(entry);
    }
    entries.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(entries)
}

pub(crate) fn read_blob(
    binding: &ProtectedHistoryBindingV1,
    blob: &ProtectedHistoryBlobV1,
) -> Result<Vec<u8>, ProtectedHistoryError> {
    if blob_identity(blob)? != blob.identity
        || blob.size != blob.metadata.size
        || blob.content_identity != blob.metadata.content_identity
    {
        return Err(ProtectedHistoryError::ObjectInvalid);
    }
    let name = identity_file_name(&blob.content_identity)?;
    let (bytes, metadata) =
        read_exact_file(&binding.blob_root, name, 0, Some(&blob.content_identity))?;
    if bytes.len() as u64 != blob.size
        || metadata.uid() != blob.metadata.owner_uid
        || metadata.mode() & 0o7777 != blob.metadata.mode
        || metadata.dev() != blob.metadata.device
        || metadata.ino() != blob.metadata.inode
        || metadata.nlink() != blob.metadata.link_count
        || metadata.len() != blob.metadata.size
    {
        return Err(ProtectedHistoryError::ObjectInvalid);
    }
    Ok(bytes)
}

fn blob_identity(blob: &ProtectedHistoryBlobV1) -> Result<String, ProtectedHistoryError> {
    let mut canonical = blob.clone();
    canonical.identity.clear();
    message_identity(HISTORY_BLOB_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| ProtectedHistoryError::ObjectInvalid)
}

fn catalog_entry_identity(
    entry: &ProtectedHistoryCatalogEntryV1,
) -> Result<String, ProtectedHistoryError> {
    let mut canonical = entry.clone();
    canonical.identity.clear();
    message_identity(HISTORY_CATALOG_ENTRY_IDENTITY_DOMAIN_V1, &canonical)
        .map_err(|_| ProtectedHistoryError::ObjectInvalid)
}

fn persist_exact_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<(), ProtectedHistoryError> {
    let directory_fd = open_protected_directory(directory, expected_owner_uid)?;
    if let Some((existing, _)) =
        try_read_exact_file_at(&directory_fd, name, expected_owner_uid, None)?
    {
        return if existing == bytes {
            sync_existing_file_at(&directory_fd, name)?;
            Ok(())
        } else {
            Err(ProtectedHistoryError::ObjectInvalid)
        };
    }
    let mut suffix = [0_u8; 16];
    getrandom::getrandom(&mut suffix).map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
    let temporary = format!(
        ".history-{}.tmp",
        suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let temporary_c =
        CString::new(temporary.as_str()).map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
    let destination_c = CString::new(name).map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
    let descriptor = unsafe {
        libc::openat(
            directory_fd.as_raw_fd(),
            temporary_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(ProtectedHistoryError::PersistenceFailed);
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                directory_fd.as_raw_fd(),
                temporary_c.as_ptr(),
                directory_fd.as_raw_fd(),
                destination_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
                && try_read_exact_file_at(&directory_fd, name, expected_owner_uid, None)?
                    .is_some_and(|(existing, _)| existing == bytes)
            {
                sync_existing_file_at(&directory_fd, name)?;
                return Ok(());
            }
            return Err(ProtectedHistoryError::PersistenceFailed);
        }
        if unsafe { libc::fsync(directory_fd.as_raw_fd()) } != 0 {
            return Err(ProtectedHistoryError::PersistenceFailed);
        }
        Ok(())
    })();
    unsafe {
        libc::unlinkat(directory_fd.as_raw_fd(), temporary_c.as_ptr(), 0);
    }
    result
}

fn sync_existing_file_at(directory: &OwnedFd, name: &str) -> Result<(), ProtectedHistoryError> {
    let name = CString::new(name).map_err(|_| ProtectedHistoryError::ObjectInvalid)?;
    let descriptor = open_exact_readonly_at(directory, &name)
        .map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
    let file = unsafe { File::from_raw_fd(descriptor) };
    file.sync_all()
        .map_err(|_| ProtectedHistoryError::PersistenceFailed)?;
    if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
        return Err(ProtectedHistoryError::PersistenceFailed);
    }
    Ok(())
}

fn open_exact_readonly_at(directory: &OwnedFd, name: &CString) -> std::io::Result<i32> {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_XDEV;
    let mut descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        ) as i32
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(error);
        }
        // The verified directory descriptor and single-component name make openat with
        // O_NOFOLLOW equivalent for this exact-file lookup on kernels or sandboxes that do not
        // expose openat2.
        descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(descriptor)
}

fn read_exact_file(
    directory: &Path,
    name: &str,
    expected_owner_uid: u32,
    expected_identity: Option<&str>,
) -> Result<(Vec<u8>, std::fs::Metadata), ProtectedHistoryError> {
    let directory = open_protected_directory(directory, expected_owner_uid)?;
    try_read_exact_file_at(&directory, name, expected_owner_uid, expected_identity)?
        .ok_or(ProtectedHistoryError::StoreUnavailable)
}

fn try_read_exact_file_at(
    directory: &OwnedFd,
    name: &str,
    expected_owner_uid: u32,
    expected_identity: Option<&str>,
) -> Result<Option<(Vec<u8>, std::fs::Metadata)>, ProtectedHistoryError> {
    let name = CString::new(name).map_err(|_| ProtectedHistoryError::ObjectInvalid)?;
    let descriptor = match open_exact_readonly_at(directory, &name) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                eprintln!(
                    "ota-authority-launcher: protected history file failed stage=open errno={}",
                    error.raw_os_error().unwrap_or_default()
                );
                Err(ProtectedHistoryError::StoreUnavailable)
            };
        }
    };
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedHistoryError::StoreUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > ota_authority_protocol::MAX_HISTORY_RESPONSE_BYTES_V1
    {
        eprintln!(
            "ota-authority-launcher: protected history file failed stage=metadata file={} uid={} mode={:o} links={} bytes={}",
            metadata.is_file(),
            metadata.uid(),
            metadata.mode() & 0o7777,
            metadata.nlink(),
            metadata.len()
        );
        return Err(ProtectedHistoryError::ObjectInvalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut bytes))
        .map_err(|_| {
            eprintln!("ota-authority-launcher: protected history file failed stage=read");
            ProtectedHistoryError::StoreUnavailable
        })?;
    if expected_identity
        .is_some_and(|identity| format!("sha256:{:x}", Sha256::digest(&bytes)) != identity)
    {
        eprintln!("ota-authority-launcher: protected history file failed stage=digest");
        return Err(ProtectedHistoryError::ObjectInvalid);
    }
    Ok(Some((bytes, metadata)))
}

fn verified_file_metadata(
    directory: &Path,
    name: &str,
    expected_owner_uid: u32,
    expected_identity: Option<&str>,
) -> Result<ProtectedHistoryFileMetadataV1, ProtectedHistoryError> {
    let (bytes, metadata) =
        read_exact_file(directory, name, expected_owner_uid, expected_identity)?;
    Ok(ProtectedHistoryFileMetadataV1 {
        owner_uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
        size: metadata.len(),
        content_identity: format!("sha256:{:x}", Sha256::digest(&bytes)),
    })
}

fn open_protected_directory(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<OwnedFd, ProtectedHistoryError> {
    verify_protected_directory(path, expected_owner_uid, Path::new("/"))
        .map_err(|_| ProtectedHistoryError::StoreUnavailable)?;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ProtectedHistoryError::StoreUnavailable)?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(ProtectedHistoryError::StoreUnavailable);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != expected_owner_uid
        || metadata.st_mode & 0o022 != 0
    {
        return Err(ProtectedHistoryError::StoreUnavailable);
    }
    Ok(descriptor)
}

fn list_directory_names(
    path: &Path,
    expected_owner_uid: u32,
) -> Result<Vec<String>, ProtectedHistoryError> {
    let directory = open_protected_directory(path, expected_owner_uid)?;
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(ProtectedHistoryError::StoreUnavailable);
    }
    let directory_stream = unsafe { libc::fdopendir(duplicate) };
    if directory_stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(ProtectedHistoryError::StoreUnavailable);
    }
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory_stream) };
        if entry.is_null() {
            let failed = unsafe { *libc::__errno_location() } != 0;
            unsafe { libc::closedir(directory_stream) };
            return if failed {
                Err(ProtectedHistoryError::StoreUnavailable)
            } else {
                names.sort();
                Ok(names)
            };
        }
        let name = match unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_str() {
            Ok(name) => name,
            Err(_) => {
                unsafe { libc::closedir(directory_stream) };
                return Err(ProtectedHistoryError::ObjectInvalid);
            }
        };
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
}

fn namespace_path(root: &Path, identity: &str) -> Result<PathBuf, ProtectedHistoryError> {
    Ok(root.join(identity_file_name(identity)?))
}

fn identity_file_name(identity: &str) -> Result<&str, ProtectedHistoryError> {
    identity
        .strip_prefix("sha256:")
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or(ProtectedHistoryError::ObjectInvalid)
}

fn is_internal_temporary_name(name: &str) -> bool {
    name.strip_prefix(".history-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

fn is_sha256(value: &str) -> bool {
    identity_file_name(value).is_ok()
}

fn is_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn catalog_temporary_names_are_closed_and_canonical() {
        assert!(is_internal_temporary_name(
            ".history-0123456789abcdef0123456789abcdef.tmp"
        ));
        assert!(!is_internal_temporary_name(
            ".history-0123456789ABCDEF0123456789ABCDEF.tmp"
        ));
        assert!(!is_internal_temporary_name(".history-short.tmp"));
        assert!(!is_internal_temporary_name("catalog.json"));
    }

    fn identity(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn protected_blob_publication_is_atomic_idempotent_and_alias_safe() {
        let root = tempfile::tempdir_in("/root").expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let owner = unsafe { libc::geteuid() };
        let directory = open_protected_directory(root.path(), owner).expect("protected root");
        if matches!(
            try_read_exact_file_at(&directory, "missing", owner, None),
            Err(ProtectedHistoryError::StoreUnavailable)
        ) {
            // The production store requires openat2. Emulated or older kernels must refuse
            // rather than weakening path resolution; native pressure supplies the positive
            // publication proof.
            assert_eq!(
                persist_blob(root.path(), b"archive", owner),
                Err(ProtectedHistoryError::StoreUnavailable)
            );
            return;
        }
        let first = persist_blob(root.path(), b"archive", owner).expect("first blob");
        let second = persist_blob(root.path(), b"archive", owner).expect("same blob");
        assert_eq!(first, second);

        let path = root
            .path()
            .join(identity_file_name(&first.content_identity).expect("name"));
        fs::remove_file(&path).expect("remove blob");
        std::os::unix::fs::symlink("elsewhere", &path).expect("alias");
        assert_eq!(
            persist_blob(root.path(), b"archive", owner),
            Err(ProtectedHistoryError::StoreUnavailable)
        );
    }

    #[test]
    fn repository_mapping_is_exact_and_never_falls_back() {
        let working = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: identity('1'),
            logical_path: String::from("/srv/repo"),
            device: 1,
            inode: 2,
        };
        let mapping = ProtectedHistoryRepositoryMappingV1 {
            schema_version: 1,
            identity: identity('2'),
            repository_binding_identity: identity('3'),
            catalog_namespace_identity: identity('4'),
            authority_id: String::from("release"),
            working_directory: working.clone(),
        };
        let mut binding = ProtectedHistoryBindingV1 {
            schema_version: 1,
            identity: identity('5'),
            protocol_profile: ota_authority_protocol::SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            socket_path: PathBuf::from(HISTORY_SOCKET_PATH),
            socket_group_gid: 1001,
            installation_manifest_identity: identity('0'),
            installed_client_path: PathBuf::from("/usr/local/bin/ota"),
            installed_client_identity: identity('6'),
            operator_uid: 1001,
            operator_gid: 1001,
            operator_profile_identity: identity('7'),
            service_unit_identity: identity('8'),
            socket_unit_identity: identity('9'),
            blob_root: PathBuf::from(HISTORY_BLOB_ROOT),
            catalog_root: PathBuf::from(HISTORY_CATALOG_ROOT),
            maximum_response_bytes: 1024,
            maximum_entry_count: 1,
            mappings: vec![mapping],
        };
        assert!(select_mapping(&binding, "release", &working).is_ok());
        assert!(select_mapping(&binding, "other", &working).is_err());
        let mut moved = working;
        moved.inode += 1;
        assert!(select_mapping(&binding, "release", &moved).is_err());

        assert_eq!(binding.blob_root, Path::new(HISTORY_BLOB_ROOT));
        assert_eq!(binding.catalog_root, Path::new(HISTORY_CATALOG_ROOT));
        assert!(has_canonical_storage_roots(&binding));
        binding.blob_root = PathBuf::from("/var/lib/ota/history/blobs");
        assert!(!has_canonical_storage_roots(&binding));
    }

    #[test]
    fn only_launcher_owned_temporary_names_are_ignored() {
        assert!(is_internal_temporary_name(
            ".history-00112233445566778899aabbccddeeff.tmp"
        ));
        assert!(!is_internal_temporary_name(".history-short.tmp"));
        assert!(!is_internal_temporary_name(
            ".history-00112233445566778899AABBCCDDEEFF.tmp"
        ));
        assert!(!is_internal_temporary_name("catalog.json"));
    }
}
