mod fixtures;

use std::net::SocketAddr;

use fedimint_api::task::TaskGroup;
use fixtures::fixtures;
use ln_gateway::{config::GatewayConfig, rpc::rpc_client::RpcClient};
use mint_client::FederationId;
use url::Url;

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_authentication() {
    let gw_address = SocketAddr::from(([127, 0, 0, 1], 10000));
    let client = RpcClient::new(Url::parse(&format!("http://{}", gw_address)).unwrap());

    let cfg = GatewayConfig {
        password: "password".into(),
        default_federation: FederationId("default_fed".into()),
        address: gw_address,
    };

    let mut gateway = fixtures(cfg);
    let task_group = TaskGroup::new();

    task_group
        .spawn(
            "run gateway",
            |handle| async move { gateway.run(handle).await },
        )
        .await;

    // Test gateway authentication on `get_info` function
    // *  `get_info` with correct password succeeds
    // *  `get_info` with incorrect password fails
    let res = client.get_info("password".into()).await;
    assert_eq!(true, res.is_err());

    let res = client.get_info("getinfo".into()).await;
    assert_eq!(true, res.is_err());

    // TODO: Test gateway authentication on other admin functions

    task_group.shutdown().await;
}
