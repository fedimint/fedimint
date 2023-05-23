//! Gateway integration test suite
//!
//! This crate contains integration tests for the gateway API
//! and business logic.
mod fixtures;

use fedimint_testing::federation::FederationTest;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload};

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
    let (_, rpc, fed1, fed2, _) = fixtures::fixtures(None).await;

    assert_eq!(rpc.get_info().await.unwrap().federations.len(), 0);

    let id1 = fed1.connection_code().id;
    let id2 = fed2.connection_code().id;

    connect_federations(&rpc, &[fed1, fed2]).await.unwrap();

    let info = rpc.get_info().await.unwrap();

    assert_eq!(info.federations.len(), 2);
    assert!(info
        .federations
        .iter()
        .any(|info| info.federation_id == id1));
    assert!(info
        .federations
        .iter()
        .any(|info| info.federation_id == id2));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // balance query needs mint module but that is not configured in fixtures
async fn gatewayd_shows_balance_for_any_connected_federation() {
    // TODO: Merge with `gatewayd_shows_info_about_all_connected_federations`
    // after Issue #2508 is resolved
    let (_, rpc, fed1, fed2, _) = fixtures::fixtures(None).await;

    let id1 = fed1.connection_code().id;
    let id2 = fed2.connection_code().id;

    connect_federations(&rpc, &[fed1, fed2]).await.unwrap();

    let bal1 = rpc
        .get_balance(BalancePayload { federation_id: id1 })
        .await
        .unwrap();

    assert_eq!(bal1.msats, 0);

    let bal2 = rpc
        .get_balance(BalancePayload { federation_id: id2 })
        .await
        .unwrap();

    assert_eq!(bal2.msats, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // deposit needs wallet module,
          // balance query needs mint module,
          // both are not configured in fixtures
async fn gatewayd_allows_deposit_to_any_connected_federation() {
    let (_, rpc, fed, _, bitcoin) = fixtures::fixtures(None).await;

    let id = fed.connection_code().id;

    connect_federations(&rpc, &[fed]).await.unwrap();

    let addr = rpc
        .get_deposit_address(DepositAddressPayload { federation_id: id })
        .await
        .unwrap();
    let amt_btc = bitcoin::Amount::from_btc(1.0).unwrap();
    let (proof, tx) = bitcoin.send_and_mine_block(&addr, amt_btc).await;

    let _ = rpc
        .deposit(DepositPayload {
            federation_id: id,
            txout_proof: proof,
            transaction: tx,
        })
        .await
        .unwrap();

    let bal = rpc
        .get_balance(BalancePayload { federation_id: id })
        .await
        .unwrap();

    assert_eq!(bal.msats, amt_btc.to_sat() * 1000);
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

pub async fn connect_federations(
    rpc: &GatewayRpcClient,
    feds: &[FederationTest],
) -> anyhow::Result<()> {
    for fed in feds {
        let connect = fed.connection_code().to_string();
        rpc.connect_federation(ConnectFedPayload { connect })
            .await?;
    }
    Ok(())
}
