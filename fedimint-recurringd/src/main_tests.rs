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
    .expect_err("empty bearer token must be rejected");

    assert!(
        error.to_string().contains("bearer token must not be empty"),
        "unexpected error: {error}"
    );
}
