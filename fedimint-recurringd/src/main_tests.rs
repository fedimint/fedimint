use clap::Parser as _;
use fedimint_core::Amount;
use fedimint_recurringd::{MAX_SENDABLE_MSAT, MIN_SENDABLE_MSAT};

use super::{CliOpts, check_lnurl_amount};

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

#[test]
fn lnurl_amount_must_be_within_the_advertised_range() {
    for msats in [MIN_SENDABLE_MSAT, MAX_SENDABLE_MSAT] {
        assert_eq!(check_lnurl_amount(Amount::from_msats(msats)), Ok(()));
    }

    for msats in [0, MAX_SENDABLE_MSAT + 1, u64::MAX] {
        assert_eq!(
            check_lnurl_amount(Amount::from_msats(msats)),
            Err(format!(
                "Amount must be between {MIN_SENDABLE_MSAT} and {MAX_SENDABLE_MSAT} msat"
            )),
            "accepted {msats} msat"
        );
    }
}
