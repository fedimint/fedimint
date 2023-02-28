use anyhow::Result;
use fedimint_core::config::ServerModuleGenRegistry;
use fedimint_core::module::DynServerModuleGen;
use fedimint_core::task::TaskGroup;
use fedimint_ln::LightningGen;
use fedimint_mint::MintGen;
use fedimint_testing::btc::fixtures::FakeBitcoinTest;
use fedimint_testing::btc::BitcoinTest;
use fedimint_testing::ln::fixtures::FakeLightningTest;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory};
use ln_gateway::lnrpc_client::DynLnRpcClient;
use ln_gateway::Gateway;
use mint_client::module_decode_stubs;
use mint_client::modules::wallet::WalletGen;
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
    let module_gens = ServerModuleGenRegistry::from(vec![
        DynServerModuleGen::from(WalletGen),
        DynServerModuleGen::from(MintGen),
        DynServerModuleGen::from(LightningGen),
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
