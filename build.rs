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

use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=Cargo.lock");

    if let Some(head_ref) = git_output(["symbolic-ref", "-q", "HEAD"]) {
        println!(
            "cargo:rerun-if-changed={}",
            Path::new(".git").join(head_ref.trim()).display()
        );
    }
    if let Some(commit) = git_output(["rev-parse", "HEAD"]) {
        println!(
            "cargo:rustc-env=OTA_LAUNCHER_BUILD_COMMIT={}",
            commit.trim()
        );
    }
    if git_is_dirty() {
        println!("cargo:rustc-env=OTA_LAUNCHER_BUILD_DIRTY=1");
    }
    if let Some(revision) = protocol_revision_from_lockfile() {
        println!("cargo:rustc-env=OTA_PROTOCOL_BUILD_REVISION={revision}");
    }
}

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())??
        .trim()
        .to_owned()
        .into()
}

fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .is_some_and(|output| {
            output.status.success() && porcelain_has_source_changes(&output.stdout)
        })
}

fn porcelain_has_source_changes(output: &[u8]) -> bool {
    output
        .split(|byte| *byte == b'\n')
        .any(|line| !line.is_empty() && line != b"?? .cargo-ok")
}

fn protocol_revision_from_lockfile() -> Option<String> {
    let lockfile = fs::read_to_string("Cargo.lock").ok()?;
    let package = lockfile
        .split("[[package]]")
        .find(|package| package.contains("name = \"ota-authority-protocol\""))?;
    let source = package
        .lines()
        .find_map(|line| line.trim().strip_prefix("source = \"")?.strip_suffix('"'))?;
    let revision = source.rsplit_once('#')?.1;
    (revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| revision.to_ascii_lowercase())
}
