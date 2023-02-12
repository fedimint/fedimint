//! Integration test suite
//!
//! This crate contains integration tests that work be creating
//! per-test federation, ln-gatewa and driving bitcoind and lightning
//! nodes to exercise certain behaviors on it.
//!
//! We run them in two modes:
//!
//! * With mocks - fake implementations of Lightning and Bitcoin node that only
//!   simulate the real behavior. These are instantiated per test.
//! * Without mocks - against real bitcoind and lightningd.
//!
//! When running against real bitcoind, the other tests might create
//! new blocks and transactions, so the tests can't expect to have
//! exclusive control over it. When it is really necessary, `lock_exclusive`
//! can be used to achieve it, but that makes the given test run serially
//! is thus udesireable.
mod fixtures;

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use fedimint_core::api::WsClientConnectInfo;
use fedimint_core::config::FederationId;
use fixtures::{fixtures, Fixtures};
use ln_gateway::rpc::rpc_client::{Error, Response, RpcClient};
use ln_gateway::rpc::{
    BalancePayload, ConnectFedPayload, DepositAddressPayload, DepositPayload, WithdrawPayload,
};
use ln_gateway::utils::retry;
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_authentication() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fedimint::consensus=warn")),
        )
        .init();
    let gw_password = "password".to_string();
    let gw_port = portpicker::pick_unused_port().expect("Failed to pick port");
    let gw_listen = SocketAddr::from(([127, 0, 0, 1], gw_port));
    let gw_api_addr = Url::parse(&format!("http://{gw_listen}")).expect("Invalid gateway address");
    let federation_id = FederationId::dummy();

    let Fixtures {
        bitcoin,
        gateway,
        mut task_group,
    } = fixtures(gw_api_addr.clone()).await?;

    // Run gateway in an isolate thread, so we dont block the test thread
    let password = gw_password.clone();
    task_group
        .spawn("Run Gateway", move |_| async move {
            if gateway.run(gw_listen, password).await.is_err() {}
        })
        .await;

    // Create an RPC client reference
    let client_ref = &RpcClient::new(gw_api_addr);

    // Test gateway authentication on `connect_federation` function
    // * `connect_federation` with correct password succeeds
    // * `connect_federation` with incorrect password fails
    let payload = ConnectFedPayload {
        connect: serde_json::to_string(&WsClientConnectInfo {
            urls: vec![],
            id: FederationId::dummy(),
        })?,
    };
    test_auth(&gw_password, move |pw| {
        client_ref.connect_federation(pw, payload.clone())
    })
    .await?;

    // Test gateway authentication on `get_info` function
    // * `get_info` with correct password succeeds
    // * `get_info` with incorrect password fails
    test_auth(&gw_password, |pw| client_ref.get_info(pw)).await?;

    // Test gateway authentication on `get_balance` function
    // * `get_balance` with correct password succeeds
    // * `get_balance` with incorrect password fails
    let payload = BalancePayload {
        federation_id: federation_id.clone(),
    };
    test_auth(&gw_password, move |pw| {
        client_ref.get_balance(pw, payload.clone())
    })
    .await?;

    // Test gateway authentication on `get_deposit_address` function
    // * `get_deposit_address` with correct password succeeds
    // * `get_deposit_address` with incorrect password fails
    let payload = DepositAddressPayload {
        federation_id: federation_id.clone(),
    };
    test_auth(&gw_password, move |pw| {
        client_ref.get_deposit_address(pw, payload.clone())
    })
    .await?;

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
    .await?;

    // Test gateway authentication on `withdraw` function
    // * `withdraw` with correct password succeeds
    // * `withdraw` with incorrect password fails
    let payload = WithdrawPayload {
        federation_id,
        amount: bitcoin::Amount::from_sat(100),
        address: bitcoin.get_new_address().await,
    };
    test_auth(&gw_password, |pw| client_ref.withdraw(pw, payload.clone())).await?;

    task_group.shutdown_join_all(None).await
}

/// Test that a given endpoint/functionality of func fails with the wrong
/// password but works with the correct one
async fn test_auth<Fut>(gw_password: &str, func: impl Fn(String) -> Fut) -> Result<()>
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
