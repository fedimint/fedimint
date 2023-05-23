//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
mod fixtures;

use fedimint_testing::federation::FederationTest;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::ConnectFedPayload;

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_supports_connecting_multiple_federations() {
    let (_, rpc, fed1, fed2, _) = fixtures::fixtures(None).await;

    assert_eq!(rpc.get_info().await.unwrap().federations.len(), 0);

    let connection1 = fed1.connection_code();
    let info = rpc
        .connect_federation(ConnectFedPayload {
            connect: connection1.to_string(),
        })
        .await
        .unwrap();

    assert_eq!(info.federation_id, connection1.id);

    let connection2 = fed2.connection_code();
    let info = rpc
        .connect_federation(ConnectFedPayload {
            connect: connection2.to_string(),
        })
        .await
        .unwrap();
    assert_eq!(info.federation_id, connection2.id);
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
