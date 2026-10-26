use clap::Parser as _;

use super::ServerOpts;

fn opts(extra: &[&str]) -> ServerOpts {
    ServerOpts::try_parse_from(
        [
            "fedimintd",
            "--data-dir",
            "unused",
            "--esplora-url",
            "http://localhost:5000",
        ]
        .into_iter()
        .chain(extra.iter().copied()),
    )
    .unwrap_or_else(|_| panic!("test arguments must parse"))
}

#[test]
fn secret_sources_conflict_before_reading_files() {
    for name in ["password-ui", "password-api", "force-api-secrets"] {
        let direct = format!("--{name}");
        let file = format!("--{name}-file");
        let mut opts = opts(&[&direct, "sensitive-sentinel", &file, "missing"]);
        let error = opts.resolve_secrets().unwrap_err().to_string();
        assert!(error.contains("conflicts"));
        assert!(!error.contains("sensitive-sentinel"));
    }
    let mut opts = opts(&[
        "--bitcoind-url",
        "http://localhost:8332",
        "--bitcoind-username",
        "test",
        "--bitcoind-password",
        "sensitive-sentinel",
        "--bitcoind-password-file",
        "missing",
    ]);
    let error = opts.resolve_secrets().unwrap_err().to_string();
    assert!(error.contains("conflicts"));
    assert!(!error.contains("sensitive-sentinel"));
}

#[test]
fn daemons_reject_stdin_before_reading_any_file() {
    let mut opts = opts(&["--password-ui-file", "missing", "--password-api-file", "-"]);
    assert!(
        opts.resolve_secrets()
            .unwrap_err()
            .to_string()
            .contains("stdin")
    );
}

#[test]
fn invalid_api_secrets_are_redacted() {
    let mut opts = opts(&["--force-api-secrets", "sensitive-sentinel,"]);
    assert_eq!(
        opts.resolve_secrets().unwrap_err().to_string(),
        "invalid API secrets"
    );
}

#[test]
fn legacy_password_sources_remain_optional() {
    let mut opts = opts(&[]);
    opts.resolve_secrets().unwrap();
    assert!(opts.password_ui.is_none());
    assert!(opts.password_api.is_none());
}

#[test]
fn file_passwords_are_resolved_without_changing_absent_planes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let mut opts = opts(&["--password-api-file", path]);
    opts.resolve_secrets().unwrap();
    let expected = include_str!("../Cargo.toml").strip_suffix('\n').unwrap();
    assert_eq!(opts.password_api.as_deref(), Some(expected));
    assert!(opts.password_ui.is_none());
}

#[test]
fn bitcoind_password_file_alias_is_compatible() {
    for flag in ["--bitcoind-password-file", "--bitcoind-url-password-file"] {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let mut opts = opts(&[
            "--bitcoind-url",
            "http://localhost:8332",
            "--bitcoind-username",
            "test",
            flag,
            path,
        ]);
        opts.resolve_secrets().unwrap();
        assert_eq!(
            opts.bitcoind_password.as_deref(),
            Some(include_str!("../Cargo.toml").trim())
        );
    }
}

#[test]
fn environment_source_conflicts_with_file() {
    const CHILD: &str = "FM_SECRET_INPUT_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let file = std::env::var(CHILD).unwrap();
        let mut opts = opts(&[
            "--bitcoind-url",
            "http://localhost:8332",
            "--bitcoind-username",
            "test",
            &file,
            "missing",
        ]);
        let error = opts.resolve_secrets().unwrap_err().to_string();
        assert!(error.contains("conflicts"));
        assert!(!error.contains("sensitive-sentinel"));
        return;
    }
    for (env, flag) in [
        ("FM_PASSWORD_API", "--password-api-file"),
        ("FM_PASSWORD_UI", "--password-ui-file"),
        ("FM_FORCE_API_SECRETS", "--force-api-secrets-file"),
        ("FM_BITCOIND_PASSWORD", "--bitcoind-password-file"),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secret_input_tests::environment_source_conflicts_with_file",
            ])
            .env(CHILD, flag)
            .env("FM_BITCOIND_PASSWORD", "test")
            .env(env, "sensitive-sentinel")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
