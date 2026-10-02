use clap::Parser as _;

use super::{RecoveryTool, TweakSource};

fn opts() -> RecoveryTool {
    RecoveryTool {
        config: None,
        descriptor: None,
        key: None,
        key_file: None,
        network: bitcoin::Network::Bitcoin,
        strategy: TweakSource::Direct { tweak: [0; 33] },
    }
}

#[test]
fn conflicting_key_sources_fail_before_file_read() {
    let mut opts = opts();
    opts.key = Some("sensitive-sentinel".to_owned());
    opts.key_file = Some("missing".into());
    let error = opts.resolve_key().unwrap_err().to_string();
    assert!(error.contains("conflicts"));
    assert!(!error.contains("sensitive-sentinel"));
}

#[test]
fn invalid_keys_are_redacted() {
    let mut opts = opts();
    opts.key = Some("sensitive-sentinel".to_owned());
    assert_eq!(
        opts.resolve_key().unwrap_err().to_string(),
        "invalid wallet secret key"
    );
}

#[test]
fn config_does_not_require_password_or_key() {
    let opts = RecoveryTool::try_parse_from([
        "recoverytool",
        "--cfg",
        "unused",
        "utxos",
        "--db",
        "unused",
    ])
    .unwrap();
    assert!(opts.resolve_key().unwrap().is_none());
}

#[test]
fn file_requires_descriptor() {
    assert!(
        RecoveryTool::try_parse_from([
            "recoverytool",
            "--cfg",
            "unused",
            "--key-file",
            "missing",
            "utxos",
            "--db",
            "unused"
        ])
        .is_err()
    );
}

#[test]
fn reads_key_from_stdin() {
    use std::io::Write as _;
    const CHILD: &str = "FM_RECOVERY_SECRET_TEST_CHILD";
    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    if std::env::var_os(CHILD).is_some() {
        let mut opts = opts();
        opts.key_file = Some("-".into());
        assert_eq!(opts.resolve_key().unwrap().unwrap(), KEY.parse().unwrap());
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "secret_input_tests::reads_key_from_stdin"])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{KEY}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
