#![deny(clippy::pedantic)]

//! Fedimint build scripts
//!
//! Implements detection of build hash. Used both internally in all
//! public-consumed binaries of `fedimint`, and also in custom builds
//! that can included 3rd party Fedimint modules.
//!
//! To use include:
//!
//! ```norust
//! [build-dependencies]
//! fedimint-build = { version = "=0.4.0-alpha", path = "../fedimint-build" }
//! ```
//!
//! in `Cargo.toml`, and:
//!
//! ```ignore
//! fn main() {
//!     fedimint_build::set_code_version();
//! }
//! ```
//!
//! in `build.rs` script.
//!
//! This will define `FEDIMINT_BUILD_CODE_VERSION` at the build time, which can
//! be accessed via `fedimint_build_code_version_env!()` and passed to binary
//! builders like `FedimintCli::new`.
pub mod envs;

use std::env;
use std::path::Path;
use std::process::Command;

use crate::envs::{FEDIMINT_BUILD_CODE_VERSION_ENV, FORCE_GIT_HASH_ENV};

fn set_code_version_inner() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed={FORCE_GIT_HASH_ENV}");

    if let Ok(hash) = env::var(FORCE_GIT_HASH_ENV) {
        eprintln!("Forced hash via {FORCE_GIT_HASH_ENV} to {hash}");
        println!("cargo:rustc-env={FEDIMINT_BUILD_CODE_VERSION_ENV}={hash}");
        return Ok(());
    }

    // In case we are compiling a released crate we don't have a git directory, but
    // can read the version hash from .cargo_vcs_info.json
    if let Ok(file) = std::fs::File::open("./.cargo_vcs_info.json") {
        let info: serde_json::Value = serde_json::from_reader(file)
            .map_err(|e| format!("Failed to parse .cargo_vcs_info.json: {e}"))?;
        let hash = info["git"]["sha1"].as_str().ok_or_else(|| {
            format!("Failed to parse .cargo_vcs_info.json: no `.git.sha` field: {info:?}")
        })?;
        println!("cargo:rustc-env={FEDIMINT_BUILD_CODE_VERSION_ENV}={hash}");
        return Ok(());
    }

    // built somewhere in the `$HOME/.cargo/...`, probably detecting it and
    // using a release version instead.

    // Note: best effort approach to force a re-run when the git hash in
    // the local repo changes without wrecking the incremental compilation
    // completely.
    for base in [
        // The relative path of git files might vary, so we just try a lot of cases.
        // If you go deeper than that, you're silly.
        ".",
        "..",
        "../..",
        "../../..",
        "../../../..",
        "../../../../..",
    ] {
        let p = &format!("{base}/.git/HEAD");
        if Path::new(&p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
        // Common(?) `git workdir` setup
        let p = &format!("{base}/HEAD");
        if Path::new(&p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    let hash = call_cmd("git", &["rev-parse", "HEAD"])?;

    let dirty = !call_cmd("git", &["status", "--porcelain"])?.is_empty();

    let hash = if dirty {
        // Since our hash needs to be constant, mark the dirty
        // state by replacing the middle with 0s. This should
        // be noticeable enough, while letting find out the
        // root commit anyway.
        format!("{}00000000{}", &hash[0..16], &hash[(40 - 16)..40])
    } else {
        hash
    };

    println!("cargo:rustc-env={FEDIMINT_BUILD_CODE_VERSION_ENV}={hash}");

    Ok(())
}

fn call_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = match Command::new(cmd).args(args).output() {
        Ok(output) => output,
        Err(e) => {
            return Err(format!("Failed to execute `git` command: {e}"));
        }
    };

    if !output.status.success() {
        return Err(format!(
            "`git` command failed: stderr: {}; stdout: {}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }

    match String::from_utf8(output.stdout) {
        Ok(o) => Ok(o.trim().to_string()),
        Err(e) => Err(format!("Invalid UTF-8 sequence detected: {e}")),
    }
}

/// Run from a `build.rs` script to detect code version. See [`crate`] for
/// description.
pub fn set_code_version() {
    if let Err(e) = set_code_version_inner() {
        eprintln!("Failed to detect git hash version: {e}. Set {FORCE_GIT_HASH_ENV} to enforce the version and skip auto-detection.");
        println!("cargo:rustc-env={FEDIMINT_BUILD_CODE_VERSION_ENV}=0000000000000000000000000000000000000000");
    }
}
