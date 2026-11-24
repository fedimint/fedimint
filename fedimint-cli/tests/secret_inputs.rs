use std::process::{Command, Stdio};

#[test]
fn multiple_module_stdin_inputs_fail_before_database_creation() {
    let data_dir = std::env::temp_dir().join(format!(
        "fedimint-cli-stdin-preflight-{}",
        rand::random::<u128>()
    ));
    assert!(!data_dir.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_fedimint-cli"))
        .env_remove("FM_PASSWORD_API")
        .env_remove("FM_FEDERATION_SECRET_HEX")
        .args(["--data-dir"])
        .arg(&data_dir)
        .args([
            "module",
            "mint",
            "combine",
            "--notes-file",
            "-",
            "--notes-file=-",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("CLI process starts");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Only one secret input may read standard input")
    );
    assert!(!data_dir.exists(), "Preflight must not create a database");
}
