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

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use ota_authority_launcher::systemd_client::{
    InvocationRequest, RecoveryPolicy, invoke_with_recovery_policy,
};

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(name = "ota-authority-systemd-client", version, about)]
struct Cli {
    #[arg(long)]
    authority_id: String,
    #[arg(long)]
    repository: PathBuf,
    #[arg(long)]
    json: bool,
    #[cfg(feature = "systemd-admin-recovery-pressure")]
    #[arg(long)]
    administrator_controlled_recovery: bool,
    #[arg(last = true, required = true)]
    ota_arguments: Vec<String>,
}

fn main() -> std::process::ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ota-authority-systemd-client: the systemd protected launcher requires Linux");
        std::process::ExitCode::from(70)
    }

    #[cfg(target_os = "linux")]
    {
        let cli = Cli::parse();
        #[cfg(feature = "systemd-admin-recovery-pressure")]
        let recovery_policy = if cli.administrator_controlled_recovery {
            RecoveryPolicy::AdministratorControlled
        } else {
            RecoveryPolicy::Immediate
        };
        #[cfg(not(feature = "systemd-admin-recovery-pressure"))]
        let recovery_policy = RecoveryPolicy::Immediate;
        match invoke_with_recovery_policy(
            InvocationRequest {
                authority_id: cli.authority_id,
                repository: cli.repository,
                ota_arguments: cli.ota_arguments,
            },
            recovery_policy,
        ) {
            Ok(result) => {
                if cli.json {
                    match serde_json::to_string_pretty(&result) {
                        Ok(value) => println!("{value}"),
                        Err(_) => return std::process::ExitCode::from(70),
                    }
                }
                let code = result
                    .terminal
                    .exit_code
                    .and_then(|value| u8::try_from(value).ok())
                    .unwrap_or(70);
                std::process::ExitCode::from(code)
            }
            Err(error) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": false,
                            "kind": "systemd_protected_launcher_client_refusal",
                            "reason": error.reason_code(),
                            "execution_started": error.execution_started()
                        })
                    );
                } else {
                    eprintln!("ota-authority-systemd-client: {error}");
                }
                std::process::ExitCode::from(error.exit_code())
            }
        }
    }
}
