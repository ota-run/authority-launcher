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

#[cfg(unix)]
mod config;
#[cfg(test)]
mod reference_peer;
#[cfg(unix)]
mod unix;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(unix)]
use crate::config::{AUTHORITY_LAUNCHER_CONFIG_PATH, CROSSING_BROKER_STORE_PATH};

#[derive(Debug, Parser)]
#[command(name = "ota-authority-launcher", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the protected Ota binary with one authority-bound launcher session.
    Run {
        /// Non-secret authority label expected in the protected Ota broker binding.
        #[arg(long)]
        authority_id: String,

        /// Arguments passed to the protected Ota binary. Only governed execution surfaces are accepted.
        #[arg(last = true, required = true)]
        ota_args: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run {
            authority_id,
            ota_args,
        } => run(authority_id.as_str(), ota_args.as_slice()),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ota-authority-launcher: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(authority_id: &str, ota_args: &[String]) -> Result<u8, String> {
    validate_authority_label(authority_id)?;
    validate_ota_args(ota_args)?;

    #[cfg(unix)]
    {
        let config = config::load_launcher_config(AUTHORITY_LAUNCHER_CONFIG_PATH)
            .map_err(|error| error.to_string())?;
        let core_binding = config::load_core_binding(CROSSING_BROKER_STORE_PATH, authority_id)
            .map_err(|error| error.to_string())?;
        let session = config
            .session(authority_id)
            .map_err(|error| error.to_string())?;
        let broker_session_descriptor = session.broker_session_descriptor;
        let expected_peer = session.expected_peer;
        unix::launch(
            config,
            broker_session_descriptor,
            expected_peer,
            core_binding,
            ota_args,
        )
        .map_err(|error| error.to_string())
    }

    #[cfg(not(unix))]
    {
        let _ = authority_id;
        let _ = ota_args;
        Err(String::from(
            "the first authority-launcher adapter supports Unix only",
        ))
    }
}

fn validate_authority_label(value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(String::from(
            "authority_id must be a bounded non-secret label",
        ))
    }
}

fn validate_ota_args(args: &[String]) -> Result<(), String> {
    let allowed = matches!(args.first().map(String::as_str), Some("run" | "up"))
        || matches!(
            args.get(0..2),
            Some([proof, kind])
                if proof == "proof" && matches!(kind.as_str(), "runtime" | "lifecycle")
        );
    if allowed {
        Ok(())
    } else {
        Err(String::from(
            "the launcher permits only ota run, ota up, ota proof runtime, or ota proof lifecycle",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_label_is_bounded_and_non_secret() {
        assert!(validate_authority_label("platform-release.v1").is_ok());
        assert!(validate_authority_label("").is_err());
        assert!(validate_authority_label("contains whitespace").is_err());
        assert!(validate_authority_label("secret/token").is_err());
        assert!(validate_authority_label(&"a".repeat(129)).is_err());
    }

    #[test]
    fn execution_surface_is_limited_to_governed_commands() {
        assert!(validate_ota_args(&[String::from("run"), String::from("publish")]).is_ok());
        assert!(validate_ota_args(&[String::from("up")]).is_ok());
        assert!(
            validate_ota_args(&[
                String::from("proof"),
                String::from("runtime"),
                String::from("--workflow"),
                String::from("smoke"),
            ])
            .is_ok()
        );
        assert!(validate_ota_args(&[String::from("proof"), String::from("lifecycle")]).is_ok());
        assert!(validate_ota_args(&[String::from("proof")]).is_err());
        assert!(validate_ota_args(&[String::from("proof"), String::from("replay")]).is_err());
        assert!(validate_ota_args(&[String::from("self-update")]).is_err());
        assert!(validate_ota_args(&[]).is_err());
    }
}
