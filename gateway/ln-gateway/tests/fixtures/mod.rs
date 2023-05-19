use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen};
use fedimint_client_legacy::module_decode_stubs;
use fedimint_client_legacy::modules::wallet::WalletClientGen;
use fedimint_core::task::{RwLock, TaskGroup};
use fedimint_ln_client::LightningClientGen;
use fedimint_mint_client::MintClientGen;
use fedimint_testing::btc::mock::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::ln::mock::FakeLightningTest;
use fedimint_testing::ln::LightningTest;
use futures::Future;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory};
use ln_gateway::lnrpc_client::ILnRpcClient;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::{Gateway, DEFAULT_FEES};
use url::Url;

pub mod client;
pub mod fed;

pub struct Fixtures {
    pub task_group: TaskGroup,
    pub bitcoin: Box<dyn BitcoinTest>,
    pub lightning: Box<dyn LightningTest>,
    pub gateway: Gateway,
    pub rpc: GatewayRpcClient,
}

pub async fn fixtures(api_addr: Url) -> Result<Fixtures> {
    // Create a lightning rpc client
    let lnrpc: Arc<RwLock<dyn ILnRpcClient>> = Arc::new(RwLock::new(FakeLightningTest::new()));

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        client::TestGatewayClientBuilder::new(MemDbFactory.into(), api_addr.clone()).into();

    let decoders = module_decode_stubs();
    let module_gens = ClientModuleGenRegistry::from(vec![
        DynClientModuleGen::from(WalletClientGen),
        DynClientModuleGen::from(MintClientGen),
        DynClientModuleGen::from(LightningClientGen),
    ]);

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    let gateway = Gateway::new_with_lightning_connection(
        lnrpc,
        client_builder,
        decoders,
        module_gens,
        task_group.clone(),
        DEFAULT_FEES,
    )
    .await
    .unwrap();

    let rpc = GatewayRpcClient::new(api_addr, "".to_string());
    let bitcoin = Box::new(FakeBitcoinTest::new());
    let lightning = Box::new(FakeLightningTest::new());

    Ok(Fixtures {
        task_group,
        bitcoin,
        lightning,
        gateway,
        rpc,
    })
}

/// Helper for generating fixtures, passing them into test code, then shutting
/// down the task thread when the test is complete.
pub async fn test<B>(
    api_addr: Url,
    listen: Option<SocketAddr>,
    password: Option<String>,
    testfn: impl FnOnce(
        Box<dyn BitcoinTest>,
        Box<dyn LightningTest>,
        Option<Gateway>,
        GatewayRpcClient,
    ) -> B,
) -> anyhow::Result<()>
where
    B: Future<Output = ()>,
{
    let Fixtures {
        mut task_group,
        bitcoin,
        lightning,
        gateway,
        rpc,
    } = fixtures(api_addr).await?;

    if listen.is_some() && password.is_some() {
        let listen = listen.unwrap();
        let password = password.unwrap();

        gateway.spawn_webserver(listen, password).await;
        task_group
            .spawn("Run Gateway", move |handle| async move {
                if gateway.run(handle).await.is_err() {}
            })
            .await;

        // Tests a running (live) gateway instance
        testfn(bitcoin, lightning, None, rpc).await;
    } else {
        // Test a gateway instance that is not running.
        // Maybe the scenario want to run it manually.
        testfn(bitcoin, lightning, Some(gateway), rpc).await;
    }

    // wrap up gatewayd tasks within one second or be killed
    task_group
        .shutdown_join_all(Some(Duration::from_secs(1)))
        .await
}
