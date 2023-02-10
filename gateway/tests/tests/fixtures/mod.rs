use anyhow::Result;
use fedimint_api::config::ModuleGenRegistry;
use fedimint_api::module::DynModuleGen;
use fedimint_api::task::TaskGroup;
use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_testing::{
    btc::{fixtures::FakeBitcoinTest, BitcoinTest},
    ln::fixtures::FakeLightningTest,
};
use ln_gateway::{
    client::{DynGatewayClientBuilder, MemDbFactory},
    gatewayd::{gateway::Gateway, lnrpc_client::DynLnRpcClient},
};
use mint_client::{module_decode_stubs, modules::wallet::WalletGen};
use tokio::sync::mpsc;
use url::Url;

pub mod client;
pub mod fed;

pub struct Fixtures {
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: Gateway,
    pub task_group: TaskGroup,
}

pub async fn fixtures(api_addr: Url) -> Result<Fixtures> {
    // Create a lightning rpc client
    let lnrpc: DynLnRpcClient = FakeLightningTest::new().into();

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        client::TestGatewayClientBuilder::new(MemDbFactory.into(), api_addr).into();

    let decoders = module_decode_stubs();
    let module_gens = ModuleGenRegistry::from(vec![
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
    ]);

    // Create task group for controlled shutdown of the gateway
    let task_group = TaskGroup::new();

    let gateway = Gateway::new(
        lnrpc,
        client_builder,
        decoders,
        module_gens,
        task_group.clone(),
    )
    .await;
    let bitcoin = Box::new(FakeBitcoinTest::new());

    Ok(Fixtures {
        bitcoin,
        gateway,
        task_group,
    })
}
