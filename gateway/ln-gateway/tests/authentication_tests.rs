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

use fedimint_core::api::{ClientConfigDownloadToken, WsClientConnectInfo};
use fedimint_core::config::FederationId;
use fedimint_logging::TracingSetup;
use ln_gateway::rpc::rpc_client::{GatewayRpcError, GatewayRpcResult};
use ln_gateway::rpc::{
    BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload, WithdrawPayload,
};
use rand::rngs::OsRng;
use rand::Rng;
use reqwest::StatusCode;
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
            let client1 = &rpc.with_password(gw_password);
            let client2 = &rpc.with_password("bad password".to_string());

            // Create a test federation ID
            let federation_id = FederationId::dummy();

            // Test gateway authentication on `connect_federation` function
            let payload = ConnectFedPayload {
                connect: serde_json::to_string(&WsClientConnectInfo {
                    url: "ws://dummy".parse().unwrap(),
                    download_token: ClientConfigDownloadToken(OsRng::default().gen()),
                    id: federation_id,
                })
                .unwrap(),
            };
            auth_success(|| client1.connect_federation(payload.clone())).await;
            auth_fails(|| client2.connect_federation(payload.clone())).await;

            // Test gateway authentication on `get_info` function
            auth_success(|| client1.get_info()).await;
            auth_fails(|| client2.get_info()).await;

            // Test gateway authentication on `get_balance` function
            let payload = BalancePayload { federation_id };
            auth_success(|| client1.get_balance(payload.clone())).await;
            auth_fails(|| client2.get_balance(payload.clone())).await;

            // Test gateway authentication on `get_deposit_address` function
            let payload = DepositAddressPayload { federation_id };
            auth_success(|| client1.get_deposit_address(payload.clone())).await;
            auth_fails(|| client2.get_deposit_address(payload.clone())).await;

            // Test gateway authentication on `deposit` function
            let (proof, tx) = bitcoin
                .send_and_mine_block(
                    &bitcoin.get_new_address().await,
                    bitcoin::Amount::from_btc(1.0).unwrap(),
                )
                .await;
            let payload = DepositPayload {
                federation_id,
                txout_proof: proof,
                transaction: tx,
            };
            auth_success(|| client1.deposit(payload.clone())).await;
            auth_fails(|| client2.deposit(payload.clone())).await;

            // Test gateway authentication on `withdraw` function
            let payload = WithdrawPayload {
                federation_id,
                amount: bitcoin::Amount::from_sat(100),
                address: bitcoin.get_new_address().await,
            };
            auth_success(|| client1.withdraw(payload.clone())).await;
            auth_fails(|| client2.withdraw(payload.clone())).await;
        },
    )
    .await?;

    Ok(())
}

/// Test that a given endpoint/functionality of func fails with the wrong
/// password but works with the correct one
async fn auth_success<Fut, T>(func: impl Fn() -> Fut)
where
    Fut: Future<Output = GatewayRpcResult<T>>,
{
    if let Err(GatewayRpcError::BadStatus(status)) = func().await {
        assert_ne!(status, StatusCode::UNAUTHORIZED)
    }
}

async fn auth_fails<Fut, T>(func: impl Fn() -> Fut)
where
    Fut: Future<Output = GatewayRpcResult<T>>,
{
    if let Err(GatewayRpcError::BadStatus(status)) = func().await {
        assert_eq!(status, StatusCode::UNAUTHORIZED)
    }
}
