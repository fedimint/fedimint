//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
mod fixtures;

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_multiple_federations() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_shows_info_about_all_connected_federations() {
    let (_, rpc, _, _, _) = fixtures::fixtures(None).await;

    assert_eq!(rpc.get_info().await.unwrap().federations.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_shows_balance_for_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_allows_deposit_to_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_allows_withdrawal_from_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_backup_of_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_restore_of_any_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

// Internal payments within a federation should not involve the gateway. See
// Issue #613: Federation facilitates internal payments w/o involving gateway
#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_internal_invoice_within_a_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_outgoing_invoice_to_generic_ln() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_pays_outgoing_invoice_between_federations_connected() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_intercepts_htlc_and_settles_to_connected_federation() -> anyhow::Result<()> {
    // todo: implement test case

    Ok(())
}
