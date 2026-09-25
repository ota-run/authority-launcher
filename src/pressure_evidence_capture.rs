//! Root-owned custody for one closed provider-free hosted pressure evidence bundle.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ota_authority_protocol::message_identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protected_launcher_capability::{
    open_protected_directory_chain, open_root, openat2_beneath,
};

pub(crate) const CAPTURE_CONFIG_PATH: &str = "/etc/ota/secret-delivery-pressure-capture.json";
pub(crate) const CAPTURE_SOURCE_ROOT: &str = "/var/lib/ota/authority-job-evidence";
pub(crate) const CAPTURE_STORE_ROOT: &str = "/var/lib/ota/authority-launcher/hosted-evidence";
pub(crate) const CAPTURE_PUBLIC_ROOT: &str =
    "/var/lib/ota/authority-launcher-public/hosted-evidence-captures";
pub(crate) const CAPTURE_SERVICE: &str =
    "/etc/systemd/system/ota-authority-pressure-evidence-capture.service";
pub(crate) const CAPTURE_PATH_UNIT: &str =
    "/etc/systemd/system/ota-authority-pressure-evidence-capture.path";

const CONFIG_DOMAIN: &[u8] = b"ota.authority-launcher.pressure-evidence-capture-config.v1\0";
const RECORD_DOMAIN: &[u8] = b"ota.authority-launcher.pressure-evidence-capture-record.v1\0";
const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PressureEvidenceCaptureConfigV1 {
    pub schema_version: u32,
    pub record_kind: String,
    pub identity: String,
    pub installation_identity: String,
    pub request_identity: String,
    pub core_source_revision: String,
    pub launcher_source_revision: String,
    pub protocol_source_revision: String,
    pub workflow_run_id: String,
    pub workflow_run_attempt: String,
    pub job_uid: u32,
    pub job_gid: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicCaptureRecordV1 {
    schema_version: u32,
    record_kind: String,
    identity: String,
    installation_identity: String,
    request_identity: String,
    core_source_revision: String,
    launcher_source_revision: String,
    protocol_source_revision: String,
    workflow_run_id: String,
    workflow_run_attempt: String,
    capture_class: String,
    bundle_digest: String,
}

pub(crate) fn config_identity(config: &PressureEvidenceCaptureConfigV1) -> Result<String, String> {
    let mut canonical = config.clone();
    canonical.identity.clear();
    message_identity(CONFIG_DOMAIN, &canonical)
        .map_err(|_| String::from("pressure evidence capture configuration identity unavailable"))
}

pub(crate) fn capture() -> Result<u8, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(String::from(
            "root is required for pressure evidence capture",
        ));
    }
    let config = load_config()?;
    let name = format!("{}-{}", config.workflow_run_id, config.workflow_run_attempt);
    let source_root = open_job_source_root(&config)?;
    let source = File::from(
        openat2_beneath(
            source_root.as_raw_fd(),
            name.as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| String::from("pressure evidence source is unavailable"))?,
    );
    verify_directory(&source, config.job_uid, config.job_gid, 0o700)?;
    let names = directory_names(source.as_raw_fd())?;
    let (outcome, expected) = classify_bundle(&names)?;

    let store_root = open_directory(CAPTURE_STORE_ROOT, 0, 0, 0o700)?;
    if let Ok(existing) = openat2_beneath(
        store_root.as_raw_fd(),
        name.as_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    ) {
        let existing = File::from(existing);
        verify_directory(&existing, 0, 0, 0o700)?;
        let names = directory_names(existing.as_raw_fd())?;
        let (capture_class, expected) = classify_bundle(&names)?;
        let digest = captured_bundle_digest(&existing, expected)?;
        publish_record(&name, &capture_record(&config, capture_class, digest)?)?;
        return Ok(0);
    }
    let staging_name = format!(".{name}.staging");
    remove_interrupted_staging(&store_root, &staging_name)?;
    mkdir_new(store_root.as_raw_fd(), &staging_name, 0o700)?;
    let staging = File::from(
        openat2_beneath(
            store_root.as_raw_fd(),
            staging_name.as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| String::from("pressure evidence staging is unavailable"))?,
    );
    verify_directory(&staging, 0, 0, 0o700)?;

    let mut digest = Sha256::new();
    for file_name in expected {
        let bytes = read_source_file(&source, file_name, &config)?;
        digest.update(file_name.as_bytes());
        digest.update([0]);
        digest.update(&bytes);
        write_new_file(&staging, file_name, &bytes)?;
    }
    staging
        .sync_all()
        .map_err(|_| String::from("pressure evidence staging sync failed"))?;
    rename_no_replace(store_root.as_raw_fd(), &staging_name, &name)?;
    store_root
        .sync_all()
        .map_err(|_| String::from("pressure evidence store sync failed"))?;

    publish_record(
        &name,
        &capture_record(&config, outcome, format!("sha256:{:x}", digest.finalize()))?,
    )?;
    Ok(0)
}

fn capture_record(
    config: &PressureEvidenceCaptureConfigV1,
    capture_class: &str,
    bundle_digest: String,
) -> Result<PublicCaptureRecordV1, String> {
    let mut record = PublicCaptureRecordV1 {
        schema_version: 1,
        record_kind: String::from("secret_delivery_pressure_public_capture"),
        identity: String::new(),
        installation_identity: config.installation_identity.clone(),
        request_identity: config.request_identity.clone(),
        core_source_revision: config.core_source_revision.clone(),
        launcher_source_revision: config.launcher_source_revision.clone(),
        protocol_source_revision: config.protocol_source_revision.clone(),
        workflow_run_id: config.workflow_run_id.clone(),
        workflow_run_attempt: config.workflow_run_attempt.clone(),
        capture_class: capture_class.into(),
        bundle_digest,
    };
    record.identity = capture_record_identity(&record)?;
    Ok(record)
}

fn load_config() -> Result<PressureEvidenceCaptureConfigV1, String> {
    let root = open_root(Path::new("/"), 0, 0)
        .map_err(|_| String::from("pressure evidence capture configuration is unavailable"))?;
    let directory =
        open_protected_directory_chain(root.as_raw_fd(), Path::new("etc/ota"), 0, 0, false)
            .map_err(|_| String::from("pressure evidence capture configuration is unavailable"))?;
    let mut file = File::from(
        openat2_beneath(
            directory.as_raw_fd(),
            b"secret-delivery-pressure-capture.json",
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
        .map_err(|_| String::from("pressure evidence capture configuration is unavailable"))?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| String::from("pressure evidence capture configuration is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o400
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err(String::from(
            "pressure evidence capture configuration protection is invalid",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| String::from("pressure evidence capture configuration is unavailable"))?;
    let config: PressureEvidenceCaptureConfigV1 = serde_json::from_slice(&bytes)
        .map_err(|_| String::from("pressure evidence capture configuration is invalid"))?;
    if serde_jcs::to_vec(&config)
        .map_err(|_| String::from("pressure evidence capture configuration is invalid"))?
        != bytes
        || config.schema_version != 1
        || config.record_kind != "secret_delivery_pressure_evidence_capture_config"
        || config.identity != config_identity(&config)?
        || !canonical_positive_decimal(&config.workflow_run_id)
        || !canonical_positive_decimal(&config.workflow_run_attempt)
        || ![&config.installation_identity, &config.request_identity]
            .into_iter()
            .all(|identity| is_sha256_identity(identity))
        || ![
            &config.core_source_revision,
            &config.launcher_source_revision,
            &config.protocol_source_revision,
        ]
        .into_iter()
        .all(|revision| is_revision(revision))
        || config.job_uid == 0
        || config.job_gid == 0
    {
        return Err(String::from(
            "pressure evidence capture configuration is invalid",
        ));
    }
    Ok(config)
}

fn classify_bundle(
    names: &BTreeSet<String>,
) -> Result<(&'static str, &'static [&'static str]), String> {
    const SUCCESS: &[&str] = &[
        "COMPLETE",
        "SHA256SUMS",
        "client-public.json",
        "client.stderr.txt",
        "endpoint-evidence.json",
        "pressure-installation.json",
        "toolkit-loopback-evidence.json",
    ];
    const FAILURE: &[&str] = &["COMPLETE", "SHA256SUMS", "client-diagnostic.json"];
    let actual = names.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual == SUCCESS.iter().copied().collect() {
        Ok(("success_set", SUCCESS))
    } else if actual == FAILURE.iter().copied().collect() {
        Ok(("failure_diagnostic_set", FAILURE))
    } else {
        Err(String::from(
            "pressure evidence source is not a closed success or failure set",
        ))
    }
}

fn read_source_file(
    directory: &File,
    name: &str,
    config: &PressureEvidenceCaptureConfigV1,
) -> Result<Vec<u8>, String> {
    let file = File::from(
        openat2_beneath(
            directory.as_raw_fd(),
            name.as_bytes(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
        .map_err(|_| String::from("pressure evidence source file is unavailable"))?,
    );
    let before = verify_source_file(&file, name, config)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| String::from("pressure evidence source file is unavailable"))?;
    if (name != "COMPLETE" && bytes.is_empty())
        || (name == "COMPLETE" && !bytes.is_empty())
        || bytes.len() as u64 != before.len()
        || bytes.len() as u64 > MAX_FILE_BYTES
    {
        return Err(String::from("pressure evidence source file is invalid"));
    }
    let after = verify_source_file(&file, name, config)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(String::from(
            "pressure evidence source changed during capture",
        ));
    }
    Ok(bytes)
}

fn verify_source_file(
    file: &File,
    name: &str,
    config: &PressureEvidenceCaptureConfigV1,
) -> Result<fs::Metadata, String> {
    let metadata = file
        .metadata()
        .map_err(|_| String::from("pressure evidence source file is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != config.job_uid
        || metadata.gid() != config.job_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o400
        || (name != "COMPLETE" && metadata.len() == 0)
        || (name == "COMPLETE" && metadata.len() != 0)
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err(String::from(
            "pressure evidence source file protection is invalid",
        ));
    }
    Ok(metadata)
}

fn directory_names(directory: std::os::fd::RawFd) -> Result<BTreeSet<String>, String> {
    let duplicate = unsafe { libc::fcntl(directory, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(String::from("pressure evidence directory is unavailable"));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(String::from("pressure evidence directory is unavailable"));
    }
    let mut names = BTreeSet::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| String::from("pressure evidence entry is invalid"))?;
        if name != "." && name != ".." && !names.insert(name.into()) {
            unsafe { libc::closedir(stream) };
            return Err(String::from("pressure evidence entry is duplicated"));
        }
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(String::from("pressure evidence directory is unavailable"));
    }
    Ok(names)
}

fn open_directory(path: &str, uid: u32, gid: u32, mode: u32) -> Result<File, String> {
    let protected = File::from(
        open_root(Path::new(path), uid, gid)
            .map_err(|_| String::from("pressure evidence directory is unavailable"))?,
    );
    verify_directory(&protected, uid, gid, mode)?;
    let protected_metadata = protected
        .metadata()
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?;

    // `open_root` deliberately returns O_PATH. Reopen its exact verified directory for fsync.
    let directory = File::from(
        openat2_beneath(
            protected.as_raw_fd(),
            b".",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?,
    );
    verify_directory(&directory, uid, gid, mode)?;
    let directory_metadata = directory
        .metadata()
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?;
    if protected_metadata.dev() != directory_metadata.dev()
        || protected_metadata.ino() != directory_metadata.ino()
    {
        return Err(String::from(
            "pressure evidence directory protection is invalid",
        ));
    }
    Ok(directory)
}

fn open_job_source_root(config: &PressureEvidenceCaptureConfigV1) -> Result<File, String> {
    let root = open_root(Path::new("/"), 0, 0)
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?;
    let relative = Path::new(CAPTURE_SOURCE_ROOT)
        .strip_prefix("/")
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?;
    let directory = File::from(
        openat2_beneath(
            root.as_raw_fd(),
            relative.as_os_str().as_encoded_bytes(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?,
    );
    verify_directory(&directory, 0, config.job_gid, 0o770)?;
    Ok(directory)
}

fn verify_directory(file: &File, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|_| String::from("pressure evidence directory is unavailable"))?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        // Overlay-backed directories can validly report one link. Only an unlinked descriptor is
        // unsafe because captured evidence would no longer have a reachable destination.
        || metadata.nlink() == 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(String::from(
            "pressure evidence directory protection is invalid",
        ));
    }
    Ok(())
}

fn mkdir_new(parent: std::os::fd::RawFd, name: &str, mode: u32) -> Result<(), String> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| String::from("pressure evidence name is invalid"))?;
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode) } != 0 {
        return Err(String::from(
            "pressure evidence destination already exists or is unavailable",
        ));
    }
    Ok(())
}

fn remove_interrupted_staging(directory: &File, name: &str) -> Result<(), String> {
    let staging = match openat2_beneath(
        directory.as_raw_fd(),
        name.as_bytes(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    ) {
        Ok(descriptor) => File::from(descriptor),
        Err(_) => return Ok(()),
    };
    verify_directory(&staging, 0, 0, 0o700)?;
    let allowed = [
        "COMPLETE",
        "SHA256SUMS",
        "client-diagnostic.json",
        "client-public.json",
        "client.stderr.txt",
        "endpoint-evidence.json",
        "pressure-installation.json",
        "toolkit-loopback-evidence.json",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    for entry in directory_names(staging.as_raw_fd())? {
        if !allowed.contains(entry.as_str()) {
            return Err(String::from(
                "interrupted pressure evidence staging is invalid",
            ));
        }
        let descriptor = openat2_beneath(
            staging.as_raw_fd(),
            entry.as_bytes(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
        .map_err(|_| String::from("interrupted pressure evidence staging is invalid"))?;
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| String::from("interrupted pressure evidence staging is invalid"))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o400
        {
            return Err(String::from(
                "interrupted pressure evidence staging is invalid",
            ));
        }
        let entry = std::ffi::CString::new(entry)
            .map_err(|_| String::from("interrupted pressure evidence staging is invalid"))?;
        if unsafe { libc::unlinkat(staging.as_raw_fd(), entry.as_ptr(), 0) } != 0 {
            return Err(String::from(
                "interrupted pressure evidence staging cleanup failed",
            ));
        }
    }
    let name = std::ffi::CString::new(name)
        .map_err(|_| String::from("interrupted pressure evidence staging is invalid"))?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(String::from(
            "interrupted pressure evidence staging cleanup failed",
        ));
    }
    directory
        .sync_all()
        .map_err(|_| String::from("interrupted pressure evidence staging cleanup failed"))
}

fn write_new_file(directory: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    let descriptor = crate::protected_launcher_capability::openat2_beneath_with_mode(
        directory.as_raw_fd(),
        name.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o400,
    )
    .map_err(|_| String::from("pressure evidence destination file is unavailable"))?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| String::from("pressure evidence destination persistence failed"))
}

fn captured_bundle_digest(directory: &File, expected: &[&str]) -> Result<String, String> {
    let mut digest = Sha256::new();
    for name in expected {
        let file = File::from(
            openat2_beneath(
                directory.as_raw_fd(),
                name.as_bytes(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|_| String::from("captured pressure evidence is unavailable"))?,
        );
        let metadata = file
            .metadata()
            .map_err(|_| String::from("captured pressure evidence is unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o400
            || (name != &"COMPLETE" && metadata.len() == 0)
            || (name == &"COMPLETE" && metadata.len() != 0)
            || metadata.len() > MAX_FILE_BYTES
        {
            return Err(String::from(
                "captured pressure evidence protection is invalid",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| String::from("captured pressure evidence is unavailable"))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(String::from("captured pressure evidence changed"));
        }
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(bytes);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn rename_no_replace(
    parent: std::os::fd::RawFd,
    source: &str,
    destination: &str,
) -> Result<(), String> {
    let source = std::ffi::CString::new(source)
        .map_err(|_| String::from("pressure evidence name is invalid"))?;
    let destination = std::ffi::CString::new(destination)
        .map_err(|_| String::from("pressure evidence name is invalid"))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent,
            source.as_ptr(),
            parent,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(String::from(
            "pressure evidence destination already exists or is unavailable",
        ));
    }
    Ok(())
}

fn capture_record_identity(record: &PublicCaptureRecordV1) -> Result<String, String> {
    let mut canonical = record.clone();
    canonical.identity.clear();
    message_identity(RECORD_DOMAIN, &canonical)
        .map_err(|_| String::from("pressure evidence capture record identity unavailable"))
}

fn publish_record(name: &str, record: &PublicCaptureRecordV1) -> Result<(), String> {
    let directory = open_directory(CAPTURE_PUBLIC_ROOT, 0, 0, 0o755)?;
    let bytes = serde_jcs::to_vec(record)
        .map_err(|_| String::from("pressure evidence capture record is unavailable"))?;
    publish_record_to_directory(&directory, name, &bytes, 0, 0)
}

fn publish_record_to_directory(
    directory: &File,
    name: &str,
    bytes: &[u8],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), String> {
    let temporary = format!(".{name}.json.tmp-{}", std::process::id());
    let descriptor = crate::protected_launcher_capability::openat2_beneath_with_mode(
        directory.as_raw_fd(),
        temporary.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o644,
    )
    .map_err(|_| String::from("pressure evidence capture record is unavailable"))?;
    let mut file = File::from(descriptor);
    let persistence = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| String::from("pressure evidence capture record persistence failed"))
        .and_then(|()| finalize_public_record_protection(&file, owner_uid, owner_gid, bytes.len()));
    if let Err(error) = persistence {
        drop(file);
        remove_file(directory.as_raw_fd(), &temporary);
        return Err(error);
    }
    drop(file);
    if rename_no_replace(directory.as_raw_fd(), &temporary, &format!("{name}.json")).is_err() {
        remove_file(directory.as_raw_fd(), &temporary);
        verify_existing_record(directory, name, bytes, owner_uid, owner_gid)?;
        return directory
            .sync_all()
            .map_err(|_| String::from("pressure evidence capture record sync failed"));
    }
    directory
        .sync_all()
        .map_err(|_| String::from("pressure evidence capture record sync failed"))
}

fn finalize_public_record_protection(
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_len: usize,
) -> Result<(), String> {
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
        return Err(String::from(
            "pressure evidence capture record protection is unavailable",
        ));
    }
    let metadata = file
        .metadata()
        .map_err(|_| String::from("pressure evidence capture record protection is unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o644
        || metadata.len() != expected_len as u64
    {
        return Err(String::from(
            "pressure evidence capture record protection is invalid",
        ));
    }
    file.sync_all()
        .map_err(|_| String::from("pressure evidence capture record protection is unavailable"))
}

fn remove_file(parent: i32, name: &str) {
    if let Ok(name) = std::ffi::CString::new(name) {
        unsafe {
            libc::unlinkat(parent, name.as_ptr(), 0);
        }
    }
}

fn verify_existing_record(
    directory: &File,
    name: &str,
    expected: &[u8],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(), String> {
    let descriptor = openat2_beneath(
        directory.as_raw_fd(),
        format!("{name}.json").as_bytes(),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(|_| String::from("pressure evidence capture record is unavailable"))?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| String::from("pressure evidence capture record is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o644
        || metadata.len() != expected.len() as u64
    {
        return Err(String::from(
            "existing pressure evidence capture record protection is invalid",
        ));
    }
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual)
        .map_err(|_| String::from("pressure evidence capture record is unavailable"))?;
    if actual != expected {
        return Err(String::from(
            "existing pressure evidence capture record does not match the retained bundle",
        ));
    }
    Ok(())
}

fn canonical_positive_decimal(value: &str) -> bool {
    !value.is_empty()
        && value != "0"
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_sha256_identity(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..].iter().all(u8::is_ascii_hexdigit)
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| !byte.is_ascii_uppercase())
}

fn is_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn closed_bundle_classes_cannot_be_mixed() {
        assert_eq!(
            classify_bundle(&names(&[
                "COMPLETE",
                "SHA256SUMS",
                "client-diagnostic.json",
            ]))
            .expect("failure diagnostic"),
            (
                "failure_diagnostic_set",
                &["COMPLETE", "SHA256SUMS", "client-diagnostic.json"] as &[&str]
            )
        );
        assert!(
            classify_bundle(&names(&[
                "COMPLETE",
                "SHA256SUMS",
                "client-diagnostic.json",
                "client-public.json",
            ]))
            .is_err()
        );
    }

    #[test]
    fn capture_config_identity_binds_the_exact_workflow_invocation() {
        let mut config = PressureEvidenceCaptureConfigV1 {
            schema_version: 1,
            record_kind: String::from("secret_delivery_pressure_evidence_capture_config"),
            identity: String::new(),
            installation_identity: format!("sha256:{}", "a".repeat(64)),
            request_identity: format!("sha256:{}", "b".repeat(64)),
            core_source_revision: "c".repeat(40),
            launcher_source_revision: "d".repeat(40),
            protocol_source_revision: "e".repeat(40),
            workflow_run_id: String::from("42"),
            workflow_run_attempt: String::from("1"),
            job_uid: 1001,
            job_gid: 1001,
        };
        config.identity = config_identity(&config).expect("identity");
        let original = config.identity.clone();
        config.workflow_run_attempt = String::from("2");
        assert_ne!(config_identity(&config).expect("identity"), original);
    }

    #[test]
    fn published_record_recovery_is_exact_and_refuses_unsafe_replacements() {
        let directory = tempfile::tempdir().expect("capture directory");
        let directory_file = File::open(directory.path()).expect("capture descriptor");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        publish_record_to_directory(&directory_file, "exact", b"{\"capture\":true}", uid, gid)
            .expect("initial record");
        publish_record_to_directory(&directory_file, "exact", b"{\"capture\":true}", uid, gid)
            .expect("identical recovery record");
        assert!(publish_record_to_directory(
            &directory_file,
            "exact",
            b"{\"capture\":false}",
            uid,
            gid,
        )
        .is_err());

        let symlink = directory.path().join("symlink.json");
        std::os::unix::fs::symlink("missing", &symlink).expect("unsafe record alias");
        assert!(publish_record_to_directory(&directory_file, "symlink", b"{}", uid, gid).is_err());

        publish_record_to_directory(&directory_file, "mode", b"{}", uid, gid).expect("mode record");
        fs::set_permissions(
            directory.path().join("mode.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("weaken record permissions");
        assert!(publish_record_to_directory(&directory_file, "mode", b"{}", uid, gid).is_err());
    }

    #[test]
    fn capture_directory_descriptor_is_syncable() {
        let directory = tempfile::tempdir().expect("capture directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protected capture directory mode");
        let metadata = fs::metadata(directory.path()).expect("capture metadata");
        let directory = open_directory(
            directory.path().to_str().expect("capture path"),
            metadata.uid(),
            metadata.gid(),
            0o700,
        )
        .expect("syncable capture directory");
        let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1, "capture directory flags");
        assert_eq!(flags & libc::O_PATH, 0, "capture directory is not O_PATH");
        let reopened = directory.metadata().expect("reopened capture metadata");
        assert_eq!(reopened.dev(), metadata.dev(), "capture directory device");
        assert_eq!(reopened.ino(), metadata.ino(), "capture directory inode");
        assert_eq!(reopened.mode() & 0o777, 0o700, "capture directory mode");
        directory.sync_all().expect("capture directory sync");
    }

    #[test]
    fn unlinked_capture_directory_is_refused() {
        let directory = tempfile::tempdir().expect("capture directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protected capture directory mode");
        let metadata = fs::metadata(directory.path()).expect("capture metadata");
        let retained = File::from(
            open_root(directory.path(), metadata.uid(), metadata.gid())
                .expect("retained capture directory"),
        );
        verify_directory(&retained, metadata.uid(), metadata.gid(), 0o700)
            .expect("linked capture directory");

        fs::remove_dir(directory.path()).expect("unlink capture directory");
        assert_eq!(
            retained.metadata().expect("unlinked metadata").nlink(),
            0,
            "unlinked directory descriptor"
        );
        assert!(verify_directory(&retained, metadata.uid(), metadata.gid(), 0o700).is_err());
    }

    #[test]
    fn public_record_protection_is_explicitly_finalized() {
        let directory = tempfile::tempdir().expect("capture directory");
        let path = directory.path().join("record.json");
        let mut file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("record file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restricted record mode");
        file.write_all(b"complete record")
            .and_then(|()| file.sync_all())
            .expect("record persistence");

        finalize_public_record_protection(
            &file,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            b"complete record".len(),
        )
        .expect("public record protection");
        assert_eq!(
            fs::metadata(path).expect("record metadata").mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn publication_with_service_umask_is_exactly_public() {
        const CHILD_ENV: &str = "OTA_PRESSURE_EVIDENCE_CAPTURE_UMASK_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "pressure_evidence_capture::tests::publication_with_service_umask_is_exactly_public",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .expect("isolated umask test");
            assert!(status.success(), "isolated umask test failed");
            return;
        }

        unsafe { libc::umask(0o077) };
        let directory = tempfile::tempdir().expect("capture directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .expect("public capture directory mode");
        let directory_file = File::open(directory.path()).expect("capture descriptor");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        publish_record_to_directory(&directory_file, "umask", b"{\"capture\":true}", uid, gid)
            .expect("public record");
        let metadata = fs::metadata(directory.path().join("umask.json")).expect("record metadata");
        assert_eq!(metadata.mode() & 0o777, 0o644, "exact public record mode");
    }
}
