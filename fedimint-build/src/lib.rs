use std::env;
use std::io::{self, Write};
use std::process::Command;

const FAKE_COMMIT_HASH: &str = "01234569afbe457afa1d2683a099c7af48a523c1";

pub fn set_code_version() {
    if env::var_os("CODE_VERSION").is_none() {
        let output = Command::new("git").args(["rev-parse", "HEAD"]).output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    println!("cargo:rustc-env=CODE_VERSION={}", git_hash);
                } else {
                    let error_message = String::from_utf8_lossy(&output.stderr);
                    io::stderr().write_all(error_message.as_bytes()).unwrap();
                    println!("cargo:rustc-env=CODE_VERSION={}", FAKE_COMMIT_HASH);
                }
            }
            Err(error) => {
                io::stderr()
                    .write_fmt(format_args!("Failed to execute git command: {}", error))
                    .unwrap();
                println!("cargo:rustc-env=CODE_VERSION={}", FAKE_COMMIT_HASH);
            }
        }
    }
    println!("cargo:rerun-if-env-changed=CODE_VERSION");
}
