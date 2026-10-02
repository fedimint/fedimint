use std::io::Write;

use clap::{CommandFactory, Parser};

use super::GatewayOpts;

fn opts(extra: &[&str]) -> GatewayOpts {
    let mut args = vec![
        "gatewayd",
        "--data-dir",
        "/unused",
        "--listen",
        "127.0.0.1:8175",
        "--network",
        "regtest",
        "--esplora-url",
        "http://localhost:50002",
    ];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["ldk", "--ldk-lightning-port", "9735", "--ldk-alias", "test"]);
    GatewayOpts::try_parse_from(args).unwrap()
}

#[test]
fn clap_configuration_is_valid() {
    GatewayOpts::command().debug_assert();
}

#[test]
fn files_reach_runtime_parameters() {
    let hash = bcrypt::hash("test-password", 4).unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "{hash}").unwrap();
    let mut password = tempfile::NamedTempFile::new().unwrap();
    write!(password, " first\nsecond \r\n").unwrap();
    let mut parsed = opts(&[
        "--bcrypt-password-hash-file",
        file.path().to_str().unwrap(),
        "--bcrypt-liquidity-manager-password-hash-file",
        file.path().to_str().unwrap(),
        "--bitcoind-url",
        "http://127.0.0.1:18443",
        "--bitcoind-username",
        "test",
        "--bitcoind-password-file",
        password.path().to_str().unwrap(),
    ]);
    parsed.resolve_secret_inputs().unwrap();
    assert_eq!(parsed.bitcoind_password.as_deref(), Some(" first\nsecond "));
    let params = parsed.to_gateway_parameters().unwrap();
    assert_eq!(params.bcrypt_password_hash.to_string(), hash);
    assert_eq!(
        params
            .bcrypt_liquidity_manager_password_hash
            .unwrap()
            .to_string(),
        hash
    );
}

#[test]
fn daemon_rejects_stdin_and_conflicts_without_values() {
    for extra in [
        vec!["--bcrypt-password-hash-file", "-"],
        vec![
            "--bcrypt-password-hash",
            "secret-marker",
            "--bcrypt-password-hash-file",
            "-",
        ],
        vec![
            "--bcrypt-password-hash",
            "secret-marker",
            "--bitcoind-password-file",
            "-",
        ],
        vec![
            "--bcrypt-password-hash",
            "secret-marker",
            "--bcrypt-liquidity-manager-password-hash-file",
            "-",
        ],
    ] {
        let mut parsed = opts(&extra);
        let error = parsed.resolve_secret_inputs().unwrap_err().to_string();
        assert!(!error.contains("secret-marker"));
    }
}

#[test]
fn malformed_hash_errors_are_redacted() {
    let mut parsed = opts(&["--bcrypt-password-hash", "secret-marker"]);
    parsed.resolve_secret_inputs().unwrap();
    let error = parsed.to_gateway_parameters().unwrap_err().to_string();
    assert_eq!(error, "Invalid gateway password hash");
}
