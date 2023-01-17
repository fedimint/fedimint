use cln_plugin::Error;
use fedimint_api::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_api::module::registry::ModuleDecoderRegistry;
use fedimint_api::task::TaskGroup;
use fedimint_server::config::load_from_file;
use fedimint_server::modules::ln::common::LightningDecoder;
use fedimint_server::modules::mint::common::MintDecoder;
use fedimint_server::modules::wallet::common::WalletDecoder;
use ln_gateway::client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder};
use ln_gateway::cln::{build_cln_rpc, ClnRpcRef};
use ln_gateway::config::GatewayConfig;
use ln_gateway::rpc::{GatewayRequest, GatewayRpcSender};
use ln_gateway::LnGateway;
use tokio::sync::mpsc;
use tracing::error;

/// Fedimint gateway packaged as a CLN plugin
#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    // Create message channels
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let ClnRpcRef { ln_rpc, work_dir } = build_cln_rpc(GatewayRpcSender::new(tx.clone())).await?;

    let gw_cfg_path = work_dir.clone().join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path).expect("Failed to parse config");

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder =
        StandardGatewayClientBuilder::new(work_dir.clone(), RocksDbFactory.into()).into();
    let decoders = ModuleDecoderRegistry::from_iter([
        (LEGACY_HARDCODED_INSTANCE_ID_LN, LightningDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_MINT, MintDecoder.into()),
        (LEGACY_HARDCODED_INSTANCE_ID_WALLET, WalletDecoder.into()),
    ]);

    // Create gateway instance
    let task_group = TaskGroup::new();
    let gateway = LnGateway::new(
        gw_cfg,
        decoders,
        ln_rpc,
        client_builder,
        tx,
        rx,
        task_group.clone(),
    )
    .await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all().await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
