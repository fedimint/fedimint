use clap::Parser as _;

use super::CliOpts;

#[test]
fn rejects_empty_bearer_token() {
    let error = CliOpts::try_parse_from([
        "fedimint-recurringd",
        "--api-address",
        "https://example.com",
        "--bearer-token",
        "",
        "--data-dir",
        "data",
    ])
    .expect("arguments parse")
    .resolve_bearer_token()
    .expect_err("empty bearer token must be rejected");

    assert!(
        error.to_string().contains("bearer token must not be empty"),
        "unexpected error: {error}"
    );
}

fn opts(extra: &[&str]) -> CliOpts {
    CliOpts::try_parse_from(
        [
            "fedimint-recurringd",
            "--api-address",
            "https://example.com",
            "--data-dir",
            "unused",
        ]
        .into_iter()
        .chain(extra.iter().copied()),
    )
    .unwrap()
}

#[test]
fn rejects_conflicting_sources_before_file_read() {
    let error = opts(&[
        "--bearer-token",
        "sensitive-sentinel",
        "--bearer-token-file",
        "missing",
    ])
    .resolve_bearer_token()
    .unwrap_err()
    .to_string();
    assert!(error.contains("conflicts"));
    assert!(!error.contains("sensitive-sentinel"));
}

#[test]
fn rejects_stdin() {
    assert!(
        opts(&["--bearer-token-file", "-"])
            .resolve_bearer_token()
            .unwrap_err()
            .to_string()
            .contains("stdin")
    );
}

#[test]
fn resolves_file_token() {
    let token = opts(&[
        "--bearer-token-file",
        concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
    ])
    .resolve_bearer_token()
    .unwrap();
    assert_eq!(
        token,
        include_str!("../Cargo.toml").strip_suffix('\n').unwrap()
    );
}

#[test]
fn requires_a_source() {
    assert!(
        CliOpts::try_parse_from([
            "fedimint-recurringd",
            "--api-address",
            "https://example.com",
            "--data-dir",
            "unused"
        ])
        .is_err()
    );
}

#[test]
fn environment_conflicts_with_file() {
    const CHILD: &str = "FM_RECURRING_SECRET_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let error = opts(&["--bearer-token-file", "missing"])
            .resolve_bearer_token()
            .unwrap_err()
            .to_string();
        assert!(error.contains("conflicts"));
        assert!(!error.contains("sensitive-sentinel"));
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "main_tests::environment_conflicts_with_file"])
        .env(CHILD, "1")
        .env("FM_RECURRING_API_BEARER_TOKEN", "sensitive-sentinel")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
