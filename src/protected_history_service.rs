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

//! Least-privilege protected-history socket service.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use ota_authority_protocol::{
    LAUNCHER_HISTORY_CHUNK, LAUNCHER_HISTORY_ENTRY, LAUNCHER_HISTORY_MANIFEST,
    LAUNCHER_HISTORY_MANIFEST_TERMINAL, LAUNCHER_HISTORY_OBJECT,
    LAUNCHER_HISTORY_PRE_QUERY_REFUSAL, LAUNCHER_HISTORY_QUERY_REFUSAL, LauncherHistoryChunkV1,
    LauncherHistoryEntryV1, LauncherHistoryManifestPostureV1, LauncherHistoryManifestTerminalV1,
    LauncherHistoryManifestV1, LauncherHistoryObjectKindV1, LauncherHistoryObjectV1,
    LauncherHistoryOperatorAttributionV1, LauncherHistoryOperatorPostureV1,
    LauncherHistoryPreQueryRefusalV1, LauncherHistoryQueryRefusalV1, LauncherHistoryQueryV1,
    LauncherHistoryRefusalReasonV1, LauncherWorkingDirectoryV1, MAX_FRAME_BYTES,
    MAX_HISTORY_CHUNK_PAYLOAD_BYTES_V1, SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1, decode_frame,
    encode_frame, launcher_history_chunk_v1_identity, launcher_history_entry_v1_identity,
    launcher_history_manifest_terminal_v1_identity, launcher_history_manifest_v1_identity,
    launcher_history_object_v1_identity, launcher_history_pre_query_refusal_v1_identity,
    launcher_history_query_refusal_v1_identity, launcher_history_query_v1_identity,
    launcher_working_directory_identity, message_identity,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(test)]
use crate::protected_history::{HISTORY_BLOB_ROOT, HISTORY_CATALOG_ROOT};
use crate::protected_history::{
    HISTORY_SOCKET_PATH, ProtectedHistoryBindingV1, ProtectedHistoryRepositoryMappingV1,
    load_catalog_entries, load_protected_history_binding, read_blob,
};
use ota_authority_launcher::linux_observations::{
    ObservedSessionPeer, observe_connected_peer, reconcile_connected_peer,
    revalidate_connected_peer, verify_peer_executable_identity, verify_peer_process_status,
};

const SYSTEMD_LISTEN_FD: RawFd = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CATALOG_SNAPSHOT_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-catalog-snapshot.v1\0";
const OPERATOR_PEER_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-operator-peer.v1\0";
const PROCESS_START_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.history-process-start.v1\0";

#[derive(Serialize)]
struct OperatorPeerIdentityV1<'a> {
    schema_version: u32,
    pid: u32,
    uid: u32,
    gid: u32,
    process_start_identity: String,
    executable_identity: &'a str,
    working_directory_identity: &'a str,
    operator_profile_identity: &'a str,
}

#[derive(Debug, Error)]
pub(crate) enum HistoryServiceError {
    #[error("the protected history service must run as root")]
    RootRequired,
    #[error("the protected history listener is unavailable")]
    ListenerUnavailable,
    #[error("the protected history request was refused")]
    RequestRefused,
}

enum ConnectionError {
    PreQuery(LauncherHistoryRefusalReasonV1),
    PostQuery,
}

struct PreparedHistoryResponse {
    frames: Vec<Vec<u8>>,
    terminal: LauncherHistoryManifestTerminalV1,
}

pub(crate) fn serve_once() -> Result<u8, HistoryServiceError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(HistoryServiceError::RootRequired);
    }
    let binding =
        load_protected_history_binding().map_err(|_| HistoryServiceError::ListenerUnavailable)?;
    let listener = inherited_listener(&binding)?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|_| HistoryServiceError::ListenerUnavailable)?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_TIMEOUT)))
        .map_err(|_| HistoryServiceError::ListenerUnavailable)?;
    if let Err(error) = serve_connection(&binding, &mut stream) {
        if let ConnectionError::PreQuery(reason) = error {
            let _ = write_pre_query_refusal(&mut stream, reason);
        }
        return Err(HistoryServiceError::RequestRefused);
    }
    Ok(0)
}

fn serve_connection(
    binding: &ProtectedHistoryBindingV1,
    stream: &mut UnixStream,
) -> Result<(), ConnectionError> {
    let peer = observe_connected_peer(stream).map_err(|error| {
        eprintln!(
            "ota-authority-launcher: protected history peer refused stage=observation reason={error}"
        );
        ConnectionError::PreQuery(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
    })?;
    admit_operator(binding, stream, &peer).map_err(ConnectionError::PreQuery)?;
    let working_directory = observe_working_directory(&peer).map_err(ConnectionError::PreQuery)?;
    revalidate_connected_peer(stream, &peer).map_err(|_| {
        ConnectionError::PreQuery(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
    })?;
    let operator_peer_identity = operator_peer_identity(binding, &peer, &working_directory)
        .map_err(ConnectionError::PreQuery)?;
    revalidate_connected_peer(stream, &peer).map_err(|_| {
        ConnectionError::PreQuery(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
    })?;
    let query = receive_query(stream).map_err(ConnectionError::PreQuery)?;
    let mapping = match select_live_mapping(binding, &working_directory) {
        Ok(mapping) => mapping,
        Err(reason) => {
            revalidate_operator_session(
                binding,
                stream,
                &peer,
                &working_directory,
                &operator_peer_identity,
            )
            .map_err(|_| ConnectionError::PostQuery)?;
            write_query_refusal(stream, &query, reason).map_err(|_| ConnectionError::PostQuery)?;
            return Ok(());
        }
    };
    let mut response = match build_response(binding, mapping, &query, &operator_peer_identity) {
        Ok(response) => response,
        Err(reason) => {
            revalidate_operator_session(
                binding,
                stream,
                &peer,
                &working_directory,
                &operator_peer_identity,
            )
            .map_err(|_| ConnectionError::PostQuery)?;
            write_query_refusal(stream, &query, reason).map_err(|_| ConnectionError::PostQuery)?;
            return Ok(());
        }
    };
    if let Err(reason) = revalidate_operator_session(
        binding,
        stream,
        &peer,
        &working_directory,
        &operator_peer_identity,
    ) {
        write_query_refusal(stream, &query, reason).map_err(|_| ConnectionError::PostQuery)?;
        return Ok(());
    }
    for frame in response.frames {
        stream
            .write_all(&frame)
            .map_err(|_| ConnectionError::PostQuery)?;
    }
    if revalidate_operator_session(
        binding,
        stream,
        &peer,
        &working_directory,
        &operator_peer_identity,
    )
    .is_err()
    {
        response.terminal.posture = LauncherHistoryManifestPostureV1::Incomplete;
        response.terminal.terminal_identity = String::new();
        response.terminal.terminal_identity =
            launcher_history_manifest_terminal_v1_identity(&response.terminal)
                .map_err(|_| ConnectionError::PostQuery)?;
    }
    stream
        .write_all(&typed_frame(&response.terminal).map_err(|_| ConnectionError::PostQuery)?)
        .map_err(|_| ConnectionError::PostQuery)
}

fn admit_operator(
    binding: &ProtectedHistoryBindingV1,
    stream: &UnixStream,
    peer: &ObservedSessionPeer,
) -> Result<(), LauncherHistoryRefusalReasonV1> {
    if peer.uid != binding.operator_uid || peer.gid != binding.operator_gid || peer.uid == 0 {
        eprintln!("ota-authority-launcher: protected history peer refused stage=credentials");
        return Err(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused);
    }
    revalidate_connected_peer(stream, peer).map_err(|_| {
        eprintln!("ota-authority-launcher: protected history peer refused stage=connection");
        LauncherHistoryRefusalReasonV1::PeerAdmissionRefused
    })?;
    verify_peer_process_status(peer).map_err(|_| {
        eprintln!("ota-authority-launcher: protected history peer refused stage=process_posture");
        LauncherHistoryRefusalReasonV1::PeerAdmissionRefused
    })?;
    verify_peer_executable_identity(peer, &binding.installed_client_identity).map_err(|_| {
        eprintln!("ota-authority-launcher: protected history peer refused stage=executable");
        LauncherHistoryRefusalReasonV1::PeerAdmissionRefused
    })
}

fn observe_working_directory(
    peer: &ObservedSessionPeer,
) -> Result<LauncherWorkingDirectoryV1, LauncherHistoryRefusalReasonV1> {
    let path = fs::read_link(format!("/proc/{}/cwd", peer.pid))
        .map_err(|_| LauncherHistoryRefusalReasonV1::RepositoryMappingMissing)?;
    let metadata = fs::metadata(&path)
        .map_err(|_| LauncherHistoryRefusalReasonV1::RepositoryMappingMissing)?;
    if !path.is_absolute() || !metadata.is_dir() {
        return Err(LauncherHistoryRefusalReasonV1::RepositoryMappingMissing);
    }
    let mut working = LauncherWorkingDirectoryV1 {
        schema_version: 1,
        identity: String::new(),
        logical_path: path.to_string_lossy().into_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    working.identity = launcher_working_directory_identity(&working)
        .map_err(|_| LauncherHistoryRefusalReasonV1::RepositoryMappingMissing)?;
    Ok(working)
}

fn operator_peer_identity(
    binding: &ProtectedHistoryBindingV1,
    peer: &ObservedSessionPeer,
    working_directory: &LauncherWorkingDirectoryV1,
) -> Result<String, LauncherHistoryRefusalReasonV1> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", peer.pid))
        .map_err(|_| LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)?;
    let closing = stat
        .rfind(')')
        .ok_or(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)?;
    let start_time = stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)?;
    let process_start_identity =
        message_identity(PROCESS_START_IDENTITY_DOMAIN_V1, &(peer.pid, start_time))
            .map_err(|_| LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)?;
    message_identity(
        OPERATOR_PEER_IDENTITY_DOMAIN_V1,
        &OperatorPeerIdentityV1 {
            schema_version: 1,
            pid: peer.pid,
            uid: peer.uid,
            gid: peer.gid,
            process_start_identity,
            executable_identity: binding.installed_client_identity.as_str(),
            working_directory_identity: working_directory.identity.as_str(),
            operator_profile_identity: binding.operator_profile_identity.as_str(),
        },
    )
    .map_err(|_| LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
}

fn revalidate_operator_session(
    binding: &ProtectedHistoryBindingV1,
    stream: &UnixStream,
    peer: &ObservedSessionPeer,
    expected_working_directory: &LauncherWorkingDirectoryV1,
    expected_operator_peer_identity: &str,
) -> Result<(), LauncherHistoryRefusalReasonV1> {
    revalidate_connected_peer(stream, peer)
        .and_then(|()| reconcile_connected_peer(peer, binding.operator_uid, binding.operator_gid))
        .and_then(|()| verify_peer_process_status(peer).map(|_| ()))
        .and_then(|()| verify_peer_executable_identity(peer, &binding.installed_client_identity))
        .map_err(|_| LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)?;
    let working_directory = observe_working_directory(peer)?;
    if &working_directory != expected_working_directory
        || operator_peer_identity(binding, peer, &working_directory)?
            != expected_operator_peer_identity
    {
        return Err(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused);
    }
    revalidate_connected_peer(stream, peer)
        .map_err(|_| LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
}

fn select_live_mapping<'a>(
    binding: &'a ProtectedHistoryBindingV1,
    working: &LauncherWorkingDirectoryV1,
) -> Result<&'a ProtectedHistoryRepositoryMappingV1, LauncherHistoryRefusalReasonV1> {
    let matches = binding
        .mappings
        .iter()
        .filter(|mapping| mapping.working_directory == *working)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [mapping] => Ok(*mapping),
        [] => Err(LauncherHistoryRefusalReasonV1::RepositoryMappingMissing),
        _ => Err(LauncherHistoryRefusalReasonV1::RepositoryMappingAmbiguous),
    }
}

fn receive_query(
    stream: &mut UnixStream,
) -> Result<LauncherHistoryQueryV1, LauncherHistoryRefusalReasonV1> {
    let payload =
        receive_payload(stream).map_err(|_| LauncherHistoryRefusalReasonV1::MalformedQuery)?;
    let query: LauncherHistoryQueryV1 = serde_json::from_slice(&payload)
        .map_err(|_| LauncherHistoryRefusalReasonV1::MalformedQuery)?;
    if launcher_history_query_v1_identity(&query).ok().as_deref()
        != Some(query.query_identity.as_str())
    {
        return Err(LauncherHistoryRefusalReasonV1::MalformedQuery);
    }
    Ok(query)
}

fn build_response(
    binding: &ProtectedHistoryBindingV1,
    mapping: &ProtectedHistoryRepositoryMappingV1,
    query: &LauncherHistoryQueryV1,
    operator_peer_identity: &str,
) -> Result<PreparedHistoryResponse, LauncherHistoryRefusalReasonV1> {
    let mut selected = load_catalog_entries(binding, mapping)
        .map_err(|_| LauncherHistoryRefusalReasonV1::CatalogInvalid)?;
    if let Some(identity) = query.archive_identity.as_deref() {
        selected.retain(|entry| entry.receipt_archive_identity == identity);
        if selected.len() != 1 {
            return Err(LauncherHistoryRefusalReasonV1::ObjectUnavailable);
        }
    }
    if selected.len() > binding.maximum_entry_count as usize {
        return Err(LauncherHistoryRefusalReasonV1::ResultTooLarge);
    }
    let producer = ota_authority_launcher::attestation_client::load_producer_binding()
        .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
    let mut objects = Vec::with_capacity(selected.len());
    let mut response_bytes = 0_u64;
    for entry in &selected {
        let archive = read_blob(binding, &entry.archive_blob)
            .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        let snapshot = read_blob(binding, &entry.contract_snapshot_blob)
            .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        let sidecar = read_blob(binding, &entry.sidecar_blob)
            .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        let decoded: ota_authority_protocol::LauncherFinalizationArchiveSidecarV1 =
            serde_json::from_slice(&sidecar)
                .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        ota_authority_launcher::attestation_client::verify_finalization_archive_sidecar(
            &producer, &decoded,
        )
        .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        if decoded.identity != entry.sidecar_identity
            || decoded.signed_finalization.identity != entry.signed_finalization_identity
            || decoded.signed_archive.identity != entry.signed_archive_identity
            || decoded.signed_archive.receipt_archive_identity != entry.receipt_archive_identity
            || decoded.signed_archive.crossing_transaction_identity
                != entry.crossing_transaction_identity
            || format!("sha256:{:x}", Sha256::digest(&archive)) != entry.receipt_archive_identity
            || format!("sha256:{:x}", Sha256::digest(&snapshot)) != entry.contract_snapshot_identity
        {
            return Err(LauncherHistoryRefusalReasonV1::ObjectInvalid);
        }
        response_bytes = response_bytes
            .checked_add(archive.len() as u64)
            .and_then(|value| value.checked_add(snapshot.len() as u64))
            .and_then(|value| value.checked_add(sidecar.len() as u64))
            .ok_or(LauncherHistoryRefusalReasonV1::ResultTooLarge)?;
        objects.push((archive, snapshot, sidecar));
    }
    if response_bytes > binding.maximum_response_bytes {
        return Err(LauncherHistoryRefusalReasonV1::ResultTooLarge);
    }
    let catalog_identities = selected
        .iter()
        .map(|entry| entry.identity.clone())
        .collect::<Vec<_>>();
    let catalog_snapshot_identity = message_identity(
        CATALOG_SNAPSHOT_IDENTITY_DOMAIN_V1,
        &(mapping.identity.as_str(), catalog_identities.as_slice()),
    )
    .map_err(|_| LauncherHistoryRefusalReasonV1::CatalogInvalid)?;
    let mut manifest = LauncherHistoryManifestV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_MANIFEST.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        query_identity: query.query_identity.clone(),
        repository_binding_identity: mapping.repository_binding_identity.clone(),
        catalog_namespace_identity: mapping.catalog_namespace_identity.clone(),
        operator_profile_identity: binding.operator_profile_identity.clone(),
        operator_peer_identity: operator_peer_identity.to_owned(),
        operator_attribution: LauncherHistoryOperatorAttributionV1::NonAgent,
        operator_posture: LauncherHistoryOperatorPostureV1::LeastPrivilegeOperatorPeerVerified,
        catalog_entry_identities: catalog_identities,
        total_selected_count: selected.len() as u32,
        bounded_response_bytes: response_bytes,
        catalog_snapshot_identity,
        manifest_identity: String::new(),
    };
    manifest.manifest_identity = launcher_history_manifest_v1_identity(&manifest)
        .map_err(|_| LauncherHistoryRefusalReasonV1::CatalogInvalid)?;
    let mut frames = vec![typed_frame(&manifest)?];
    for (ordinal, (catalog, (archive, snapshot, sidecar))) in
        selected.iter().zip(objects).enumerate()
    {
        append_entry_frames(
            &mut frames,
            &manifest,
            ordinal as u32,
            catalog.identity.as_str(),
            archive,
            snapshot,
            sidecar,
        )?;
    }
    let mut terminal = LauncherHistoryManifestTerminalV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_MANIFEST_TERMINAL.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        query_identity: query.query_identity.clone(),
        manifest_identity: manifest.manifest_identity,
        returned_count: selected.len() as u32,
        posture: LauncherHistoryManifestPostureV1::Complete,
        terminal_identity: String::new(),
    };
    terminal.terminal_identity = launcher_history_manifest_terminal_v1_identity(&terminal)
        .map_err(|_| LauncherHistoryRefusalReasonV1::CatalogInvalid)?;
    Ok(PreparedHistoryResponse { frames, terminal })
}

#[allow(clippy::too_many_arguments)]
fn append_entry_frames(
    frames: &mut Vec<Vec<u8>>,
    manifest: &LauncherHistoryManifestV1,
    ordinal: u32,
    catalog_identity: &str,
    archive: Vec<u8>,
    snapshot: Vec<u8>,
    sidecar: Vec<u8>,
) -> Result<(), LauncherHistoryRefusalReasonV1> {
    let archive_object = history_object(
        manifest,
        ordinal,
        catalog_identity,
        LauncherHistoryObjectKindV1::Archive,
        &archive,
    )?;
    let snapshot_object = history_object(
        manifest,
        ordinal,
        catalog_identity,
        LauncherHistoryObjectKindV1::ContractSnapshot,
        &snapshot,
    )?;
    let sidecar_object = history_object(
        manifest,
        ordinal,
        catalog_identity,
        LauncherHistoryObjectKindV1::Sidecar,
        &sidecar,
    )?;
    let mut entry = LauncherHistoryEntryV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_ENTRY.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        manifest_identity: manifest.manifest_identity.clone(),
        entry_ordinal: ordinal,
        catalog_identity: catalog_identity.to_owned(),
        archive_object_identity: archive_object.object_identity.clone(),
        contract_snapshot_object_identity: snapshot_object.object_identity.clone(),
        sidecar_object_identity: sidecar_object.object_identity.clone(),
        entry_identity: String::new(),
    };
    entry.entry_identity = launcher_history_entry_v1_identity(&entry)
        .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
    frames.push(typed_frame(&entry)?);
    append_object_frames(frames, archive_object, archive)?;
    append_object_frames(frames, snapshot_object, snapshot)?;
    append_object_frames(frames, sidecar_object, sidecar)
}

fn history_object(
    manifest: &LauncherHistoryManifestV1,
    ordinal: u32,
    catalog_identity: &str,
    kind: LauncherHistoryObjectKindV1,
    bytes: &[u8],
) -> Result<LauncherHistoryObjectV1, LauncherHistoryRefusalReasonV1> {
    let mut object = LauncherHistoryObjectV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_OBJECT.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        manifest_identity: manifest.manifest_identity.clone(),
        entry_ordinal: ordinal,
        catalog_identity: catalog_identity.to_owned(),
        object_kind: kind,
        content_identity: format!("sha256:{:x}", Sha256::digest(bytes)),
        byte_length: bytes.len() as u64,
        chunk_count: u32::try_from(bytes.len().div_ceil(MAX_HISTORY_CHUNK_PAYLOAD_BYTES_V1))
            .map_err(|_| LauncherHistoryRefusalReasonV1::ResultTooLarge)?,
        object_identity: String::new(),
    };
    object.object_identity = launcher_history_object_v1_identity(&object)
        .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
    Ok(object)
}

fn append_object_frames(
    frames: &mut Vec<Vec<u8>>,
    object: LauncherHistoryObjectV1,
    bytes: Vec<u8>,
) -> Result<(), LauncherHistoryRefusalReasonV1> {
    frames.push(typed_frame(&object)?);
    for (ordinal, payload) in bytes.chunks(MAX_HISTORY_CHUNK_PAYLOAD_BYTES_V1).enumerate() {
        let mut chunk = LauncherHistoryChunkV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_CHUNK.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            object_identity: object.object_identity.clone(),
            chunk_ordinal: ordinal as u32,
            bytes: payload.to_vec(),
            chunk_identity: String::new(),
        };
        chunk.chunk_identity = launcher_history_chunk_v1_identity(&chunk)
            .map_err(|_| LauncherHistoryRefusalReasonV1::ObjectInvalid)?;
        frames.push(typed_frame(&chunk)?);
    }
    Ok(())
}

fn write_pre_query_refusal(
    stream: &mut UnixStream,
    reason: LauncherHistoryRefusalReasonV1,
) -> Result<(), ()> {
    let reason = match reason {
        LauncherHistoryRefusalReasonV1::MalformedQuery
        | LauncherHistoryRefusalReasonV1::UnsupportedProtocol
        | LauncherHistoryRefusalReasonV1::ServiceUnavailable => reason,
        _ => LauncherHistoryRefusalReasonV1::PeerAdmissionRefused,
    };
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| ())?;
    let mut refusal = LauncherHistoryPreQueryRefusalV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_PRE_QUERY_REFUSAL.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        refusal_nonce: nonce.iter().map(|byte| format!("{byte:02x}")).collect(),
        reason,
        terminal_identity: String::new(),
    };
    refusal.terminal_identity =
        launcher_history_pre_query_refusal_v1_identity(&refusal).map_err(|_| ())?;
    stream
        .write_all(&typed_frame(&refusal).map_err(|_| ())?)
        .map_err(|_| ())
}

fn write_query_refusal(
    stream: &mut UnixStream,
    query: &LauncherHistoryQueryV1,
    reason: LauncherHistoryRefusalReasonV1,
) -> Result<(), ()> {
    let mut refusal = LauncherHistoryQueryRefusalV1 {
        schema_version: 1,
        message_kind: LAUNCHER_HISTORY_QUERY_REFUSAL.into(),
        protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
        query_identity: query.query_identity.clone(),
        reason,
        terminal_identity: String::new(),
    };
    refusal.terminal_identity =
        launcher_history_query_refusal_v1_identity(&refusal).map_err(|_| ())?;
    stream
        .write_all(&typed_frame(&refusal).map_err(|_| ())?)
        .map_err(|_| ())
}

fn typed_frame(value: &impl Serialize) -> Result<Vec<u8>, LauncherHistoryRefusalReasonV1> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| LauncherHistoryRefusalReasonV1::ServiceUnavailable)?;
    encode_frame(&payload).map_err(|_| LauncherHistoryRefusalReasonV1::ServiceUnavailable)
}

fn receive_payload(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(());
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream.read_exact(&mut frame[4..]).map_err(|_| ())?;
    decode_frame(&frame)
        .map(|payload| payload.to_vec())
        .map_err(|_| ())
}

fn inherited_listener(
    binding: &ProtectedHistoryBindingV1,
) -> Result<UnixListener, HistoryServiceError> {
    let pid = unsafe { libc::getpid() }.to_string();
    if env::var("LISTEN_PID").ok().as_deref() != Some(pid.as_str())
        || env::var("LISTEN_FDS").ok().as_deref() != Some("1")
        || binding.socket_path != Path::new(HISTORY_SOCKET_PATH)
    {
        return Err(HistoryServiceError::ListenerUnavailable);
    }
    let flags = unsafe { libc::fcntl(SYSTEMD_LISTEN_FD, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(SYSTEMD_LISTEN_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(HistoryServiceError::ListenerUnavailable);
    }
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    let metadata = fs::symlink_metadata(&binding.socket_path)
        .map_err(|_| HistoryServiceError::ListenerUnavailable)?;
    if listener
        .local_addr()
        .ok()
        .and_then(|address| address.as_pathname().map(Path::to_path_buf))
        != Some(binding.socket_path.clone())
        || !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != binding.socket_group_gid
        || metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err(HistoryServiceError::ListenerUnavailable);
    }
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    #[test]
    fn missing_repository_instance_never_falls_back() {
        let working = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::from(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            logical_path: String::from("/srv/repo"),
            device: 1,
            inode: 2,
        };
        let binding = ProtectedHistoryBindingV1 {
            schema_version: 1,
            identity: String::new(),
            protocol_profile: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            socket_path: PathBuf::from(HISTORY_SOCKET_PATH),
            socket_group_gid: 1001,
            installation_manifest_identity: working.identity.clone(),
            installed_client_path: PathBuf::from("/usr/local/bin/ota"),
            installed_client_identity: working.identity.clone(),
            operator_uid: 1001,
            operator_gid: 1001,
            operator_profile_identity: working.identity.clone(),
            service_unit_identity: working.identity.clone(),
            socket_unit_identity: working.identity.clone(),
            blob_root: PathBuf::from(HISTORY_BLOB_ROOT),
            catalog_root: PathBuf::from(HISTORY_CATALOG_ROOT),
            maximum_response_bytes: 1024,
            maximum_entry_count: 1,
            mappings: Vec::new(),
        };
        assert_eq!(
            select_live_mapping(&binding, &working),
            Err(LauncherHistoryRefusalReasonV1::RepositoryMappingMissing)
        );
    }

    #[test]
    fn objects_derive_before_entry_and_bind_archive_snapshot_and_sidecar() {
        let mut manifest = LauncherHistoryManifestV1 {
            schema_version: 1,
            message_kind: LAUNCHER_HISTORY_MANIFEST.into(),
            protocol_version: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            query_identity: identity('1'),
            repository_binding_identity: identity('2'),
            catalog_namespace_identity: identity('3'),
            operator_profile_identity: identity('4'),
            operator_peer_identity: identity('5'),
            operator_attribution: LauncherHistoryOperatorAttributionV1::NonAgent,
            operator_posture: LauncherHistoryOperatorPostureV1::LeastPrivilegeOperatorPeerVerified,
            catalog_entry_identities: vec![identity('6')],
            total_selected_count: 1,
            bounded_response_bytes: 24,
            catalog_snapshot_identity: identity('7'),
            manifest_identity: String::new(),
        };
        manifest.manifest_identity =
            launcher_history_manifest_v1_identity(&manifest).expect("manifest identity");
        let mut frames = Vec::new();
        append_entry_frames(
            &mut frames,
            &manifest,
            0,
            identity('6').as_str(),
            b"archive".to_vec(),
            b"snapshot".to_vec(),
            b"sidecar".to_vec(),
        )
        .expect("entry frames");

        let decode = |index: usize| {
            serde_json::from_slice::<serde_json::Value>(
                decode_frame(&frames[index]).expect("framed payload"),
            )
            .expect("JSON frame")
        };
        let entry: LauncherHistoryEntryV1 = serde_json::from_value(decode(0)).expect("entry");
        let archive: LauncherHistoryObjectV1 =
            serde_json::from_value(decode(1)).expect("archive object");
        let snapshot: LauncherHistoryObjectV1 =
            serde_json::from_value(decode(3)).expect("snapshot object");
        let sidecar: LauncherHistoryObjectV1 =
            serde_json::from_value(decode(5)).expect("sidecar object");

        assert_eq!(archive.manifest_identity, manifest.manifest_identity);
        assert_eq!(archive.entry_ordinal, 0);
        assert_eq!(archive.catalog_identity, identity('6'));
        assert_eq!(entry.archive_object_identity, archive.object_identity);
        assert_eq!(
            entry.contract_snapshot_object_identity,
            snapshot.object_identity
        );
        assert_eq!(entry.sidecar_object_identity, sidecar.object_identity);
        assert_eq!(
            launcher_history_entry_v1_identity(&entry).expect("entry identity"),
            entry.entry_identity
        );
        assert_ne!(entry.archive_object_identity, entry.sidecar_object_identity);
        assert_ne!(
            entry.archive_object_identity,
            entry.contract_snapshot_object_identity
        );
    }

    #[test]
    fn complete_operator_session_checkpoint_refuses_after_peer_exit() {
        let root = tempfile::tempdir().expect("temporary root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777))
            .expect("temporary root permissions");
        let repository = root.path().join("repository");
        fs::create_dir(&repository).expect("repository");
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o755))
            .expect("repository permissions");
        let socket_path = root.path().join("history-peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("history listener");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o777))
            .expect("history socket permissions");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork must succeed");
        if child == 0 {
            drop(listener);
            let repository = CString::new(repository.as_os_str().as_bytes()).unwrap_or_default();
            if unsafe { libc::chdir(repository.as_ptr()) } != 0 {
                unsafe { libc::_exit(90) };
            }
            let mut stream = match UnixStream::connect(&socket_path) {
                Ok(stream) => stream,
                Err(_) => unsafe { libc::_exit(91) },
            };
            if stream.write_all(b"ready").is_err() {
                unsafe { libc::_exit(92) };
            }
            unsafe {
                libc::pause();
                libc::_exit(0);
            }
        }

        let (mut stream, _) = listener.accept().expect("accepted operator peer");
        let mut ready = [0_u8; 5];
        stream.read_exact(&mut ready).expect("operator peer ready");
        assert_eq!(&ready, b"ready");
        let peer = observe_connected_peer(&stream).expect("observed operator peer");
        let working_directory = observe_working_directory(&peer).expect("working directory");
        let binding = ProtectedHistoryBindingV1 {
            schema_version: 1,
            identity: identity('1'),
            protocol_profile: SYSTEMD_PROTECTED_HISTORY_PROTOCOL_V1.into(),
            socket_path: PathBuf::from(HISTORY_SOCKET_PATH),
            socket_group_gid: peer.gid,
            installation_manifest_identity: identity('2'),
            installed_client_path: PathBuf::from("/proc/self/exe"),
            installed_client_identity: identity('6'),
            operator_uid: peer.uid,
            operator_gid: peer.gid,
            operator_profile_identity: identity('3'),
            service_unit_identity: identity('4'),
            socket_unit_identity: identity('5'),
            blob_root: PathBuf::from(HISTORY_BLOB_ROOT),
            catalog_root: PathBuf::from(HISTORY_CATALOG_ROOT),
            maximum_response_bytes: 1024,
            maximum_entry_count: 1,
            mappings: Vec::new(),
        };
        let peer_identity = operator_peer_identity(&binding, &peer, &working_directory)
            .expect("operator peer identity");
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(
            revalidate_operator_session(
                &binding,
                &stream,
                &peer,
                &working_directory,
                &peer_identity,
            ),
            Err(LauncherHistoryRefusalReasonV1::PeerAdmissionRefused)
        );
    }
}
