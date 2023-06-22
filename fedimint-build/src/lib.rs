use std::env;
use std::process::{Command, Stdio};

const FAKE_COMMIT_HASH: &str = "01234569afbe457afa1d2683a099c7af48a523c1";

pub fn set_code_version() {
    if env::var_os("CODE_VERSION").is_none() {
        let output = match Command::new("git")
            .args(["rev-parse", "HEAD"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
        {
            Ok(o) => o,
            Err(e) => match env::var("FEDIMINT_BUILD_ALLOW_GIT_FAIL") {
                Ok(_) => {
                    eprintln!("Failed to execute git command.");
                    println!("cargo:rustc-env=CODE_VERSION={FAKE_COMMIT_HASH}");
                    return;
                }
                Err(_) => {
                    panic!("Failed to execute git command: {e}");
                }
            },
        };

        let git_hash = if output.status.success() {
            match String::from_utf8(output.stdout) {
                Ok(hash) => hash.trim().to_string(),
                Err(_) => {
                    eprintln!("Invalid UTF-8 sequence detected.");
                    FAKE_COMMIT_HASH.to_string()
                }
            }
        } else {
            FAKE_COMMIT_HASH.to_string()
        };

        println!("cargo:rustc-env=CODE_VERSION={git_hash}");
    }
    println!("cargo:rerun-if-env-changed=CODE_VERSION");
}
