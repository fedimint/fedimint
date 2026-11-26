use std::io::Write;
use std::process::{Command, Output};

use clap::{CommandFactory, Parser};

use super::GatewayOpts;

const CHILD_TEST_COMPLETED: &str = "gateway config subprocess assertions passed";

fn run_isolated_test(name: &str, envs: &[(&str, &str)]) -> Output {
    // Clap reads configuration from the process environment. Give each child
    // only the inputs the test supplies, without modifying the parent.
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env_clear()
        .envs(envs.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Libtest exits successfully even if the exact filter matches no tests.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(CHILD_TEST_COMPLETED),
        "{name}: child did not complete the test"
    );
    output
}

fn opts(extra: &[&str]) -> GatewayOpts {
    opts_with_backend(extra, true)
}

fn opts_with_backend(extra: &[&str], esplora: bool) -> GatewayOpts {
    let mut args = vec![
        "gatewayd",
        "--data-dir",
        "/unused",
        "--listen",
        "127.0.0.1:8175",
        "--network",
        "regtest",
    ];
    if esplora {
        args.extend(["--esplora-url", "http://localhost:50002"]);
    }
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
    const MARKER: &str = "FM_TEST_GATEWAY_SECRET_FILES";
    if std::env::var_os(MARKER).is_none() {
        run_isolated_test(
            "config::tests::files_reach_runtime_parameters",
            &[(MARKER, "1")],
        );
        return;
    }

    let hash = bcrypt::hash("test-password", 4).unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "{hash}").unwrap();
    let mut password = tempfile::NamedTempFile::new().unwrap();
    write!(password, " first\nsecond \r\n").unwrap();
    let mut parsed = opts_with_backend(
        &[
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
        ],
        false,
    );
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
    println!("{CHILD_TEST_COMPLETED}");
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

#[test]
fn environment_and_file_conflicts_are_redacted() {
    // Use subprocesses rather than mutating this multithreaded test process's
    // environment. The marker only selects the child branch of this test.
    const MARKER: &str = "FM_TEST_GATEWAY_SECRET_ENV";
    if let Ok(file_option) = std::env::var(MARKER) {
        let mut args = vec![file_option.as_str(), "-"];
        if file_option != "--bcrypt-password-hash-file" {
            args.extend(["--bcrypt-password-hash", "placeholder"]);
        }
        let mut parsed = opts(&args);
        let error = parsed.resolve_secret_inputs().unwrap_err().to_string();
        assert_eq!(
            error,
            "Specify only one value or file source for each secret"
        );
        println!("{CHILD_TEST_COMPLETED}");
        return;
    }
    for (env, file_option) in [
        (
            crate::envs::FM_GATEWAY_BCRYPT_PASSWORD_HASH_ENV,
            "--bcrypt-password-hash-file",
        ),
        (
            crate::envs::FM_GATEWAY_LIQUIDITY_MANAGER_BCRYPT_PASSWORD_HASH_ENV,
            "--bcrypt-liquidity-manager-password-hash-file",
        ),
        (
            crate::envs::FM_BITCOIND_PASSWORD_ENV,
            "--bitcoind-password-file",
        ),
    ] {
        let output = run_isolated_test(
            "config::tests::environment_and_file_conflicts_are_redacted",
            &[(MARKER, file_option), (env, "environment-secret-marker")],
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("environment-secret-marker"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("environment-secret-marker"));
    }
}
