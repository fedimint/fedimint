//! Gatewayd authentication test suite
//!
//! This crate contains authentication tests for gatewayd API.
//!
//! The tests run instances of gatewayd with the following mocks:
//!
//! * mock of `ILnRpcClient` - Use a fake implementation of `ILnRpcClient` that
//!   simulates gateway lightning dependency.
//!
//! * mock of `IFederationApi` - Use a fake implementation of `IFederationApi`
//!   that simulates gateway federation client dependency.
mod fixtures;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::config::FederationId;
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::{Error, Response};
use ln_gateway::rpc::{
    BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload, WithdrawPayload,
};
use ln_gateway::utils::retry;
use url::Url;

use crate::fixtures::test;

#[tokio::test(flavor = "multi_thread")]
async fn gatewayd_api_authentication() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let gw_port = portpicker::pick_unused_port().expect("Failed to pick port");
    let gw_listen = SocketAddr::from(([127, 0, 0, 1], gw_port));
    let gw_api_addr = Url::parse(&format!("http://{gw_listen}")).expect("Invalid gateway address");
    let gw_password = "password".to_string();

    test(
        gw_api_addr.clone(),
        Some(gw_listen),
        Some(gw_password.clone()),
        |bitcoin, _, _, rpc| async move {
            // Create an RPC client reference
            let client_ref = &rpc;

            // Create a test federation ID
            let federation_id = FederationId::dummy();

            // Test gateway authentication on `connect_federation` function
            // * `connect_federation` with correct password succeeds
            // * `connect_federation` with incorrect password fails
            let payload = ConnectFedPayload {
                connect: serde_json::to_string(&WsClientConnectInfo {
                    urls: vec![],
                    id: federation_id.clone(),
                })
                .unwrap(),
            };
            test_auth(&gw_password, move |pw| {
                client_ref.connect_federation(pw, payload.clone())
            })
            .await
            .unwrap();

            // Test gateway authentication on `get_info` function
            // * `get_info` with correct password succeeds
            // * `get_info` with incorrect password fails
            test_auth(&gw_password, |pw| client_ref.get_info(pw))
                .await
                .unwrap();

            // Test gateway authentication on `get_balance` function
            // * `get_balance` with correct password succeeds
            // * `get_balance` with incorrect password fails
            let payload = BalancePayload {
                federation_id: federation_id.clone(),
            };
            test_auth(&gw_password, move |pw| {
                client_ref.get_balance(pw, payload.clone())
            })
            .await
            .unwrap();

            // Test gateway authentication on `get_deposit_address` function
            // * `get_deposit_address` with correct password succeeds
            // * `get_deposit_address` with incorrect password fails
            let payload = DepositAddressPayload {
                federation_id: federation_id.clone(),
            };
            test_auth(&gw_password, move |pw| {
                client_ref.get_deposit_address(pw, payload.clone())
            })
            .await
            .unwrap();

            // Test gateway authentication on `deposit` function
            // * `deposit` with correct password succeeds
            // * `deposit` with incorrect password fails
            let (proof, tx) = bitcoin
                .send_and_mine_block(
                    &bitcoin.get_new_address().await,
                    bitcoin::Amount::from_btc(1.0).unwrap(),
                )
                .await;
            let payload = DepositPayload {
                federation_id: federation_id.clone(),
                txout_proof: proof,
                transaction: tx,
            };
            test_auth(&gw_password, move |pw| {
                client_ref.deposit(pw, payload.clone())
            })
            .await
            .unwrap();

            // Test gateway authentication on `withdraw` function
            // * `withdraw` with correct password succeeds
            // * `withdraw` with incorrect password fails
            let payload = WithdrawPayload {
                federation_id,
                amount: bitcoin::Amount::from_sat(100),
                address: bitcoin.get_new_address().await,
            };
            test_auth(&gw_password, |pw| client_ref.withdraw(pw, payload.clone()))
                .await
                .unwrap();
        },
    )
    .await?;

    Ok(())
}

/// Test that a given endpoint/functionality of func fails with the wrong
/// password but works with the correct one
async fn test_auth<Fut>(gw_password: &str, func: impl Fn(String) -> Fut) -> anyhow::Result<()>
where
    Fut: Future<Output = Result<Response, Error>>,
{
    assert_eq!(
        retry(
            "fn".to_string(),
            || async {
                func(format!("foobar{gw_password}"))
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            },
            Duration::from_secs(1),
            3,
        )
        .await?
        .status(),
        401
    );
    assert_ne!(
        retry(
            "fn".to_string(),
            || async {
                func(gw_password.to_string())
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            },
            Duration::from_secs(1),
            3,
        )
        .await?
        .status(),
        401
    );

    Ok(())
}
