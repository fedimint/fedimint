mod fixtures;

use std::net::SocketAddr;

use anyhow::Result;
use fixtures::{fixtures, Fixtures};
use ln_gateway::{config::GatewayConfig, rpc::rpc_client::RpcClient};
use mint_client::FederationId;
use url::Url;

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_authentication() -> Result<()> {
    let gw_password = "password".to_string();
    let gw_address = SocketAddr::from(([127, 0, 0, 1], 10000));
    let federation_id = FederationId("test_fed".into());

    let cfg = GatewayConfig {
        password: gw_password.clone(),
        default_federation: federation_id.clone(),
        address: gw_address,
    };

    let Fixtures {
        gateway,
        mut task_group,
    } = fixtures(cfg)?;

    // Run gateway in an isolate thread, so we dont block the test thread
    task_group
        .spawn("Run Gateway", move |_| async move {
            if gateway.run().await.is_err() {}
        })
        .await;

    // Create an RPC client
    let client = RpcClient::new(
        Url::parse(&format!("http://{}", gw_address)).expect("Invalid gateway address"),
    );

    // Test gateway authentication on `get_info` function
    // *  `get_info` with correct password succeeds
    // *  `get_info` with incorrect password fails
    assert_eq!(client.get_info(gw_password).await?.status(), 200);
    assert_eq!(client.get_info("getinfo".to_string()).await?.status(), 401);

    // TODO:
    // Test gateway authentication on `get_balance` function
    // *  `get_balance` with correct password succeeds
    // *  `get_balance` with incorrect password fails

    // TODO:
    // Test gateway authentication on `get_deposit_address` function
    // *  `get_deposit_address` with correct password succeeds
    // *  `get_deposit_address` with incorrect password fails

    // TODO:
    // Test gateway authentication on `deposit` function
    // *  `deposit` with correct password succeeds
    // *  `deposit` with incorrect password fails

    // TODO:
    // Test gateway authentication on `withdraw` function
    // *  `withdraw` with correct password succeeds
    // *  `withdraw` with incorrect password fails

    // TODO:
    // Test gateway authentication on `register_federation` function
    // *  `register_federation` with correct password succeeds
    // *  `register_federation` with incorrect password fails

    task_group.shutdown_join_all().await
}
