use cln_plugin::Error;
use fedimint_core::config::{load_from_file, ModuleGenRegistry};
use fedimint_core::core::{
    LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::DynModuleGen;
use fedimint_core::task::TaskGroup;
use fedimint_core::ServerModule;
use ln_gateway::client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder};
use ln_gateway::cln::{build_cln_rpc, ClnRpcRef};
use ln_gateway::config::GatewayConfig;
use ln_gateway::rpc::{GatewayRequest, GatewayRpcSender};
use ln_gateway::LnGateway;
use mint_client::modules::ln::{Lightning, LightningGen};
use mint_client::modules::mint::{Mint, MintGen};
use mint_client::modules::wallet::{Wallet, WalletGen};
use tokio::sync::mpsc;
use tracing::error;

/// Fedimint gateway packaged as a CLN plugin
// Use CLN_PLUGIN_LOG=<log-level> to enable debug logging from within cln-plugin
#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("CODE_VERSION"));
            return Ok(());
        }
    }

    // Create message channels
    let (tx, rx) = mpsc::channel::<GatewayRequest>(100);

    let ClnRpcRef { ln_rpc, work_dir } = build_cln_rpc(GatewayRpcSender::new(tx.clone())).await?;

    let gw_cfg_path = work_dir.clone().join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path).expect("Failed to parse config");

    // Create federation client builder
    let client_builder: DynGatewayClientBuilder = StandardGatewayClientBuilder::new(
        work_dir.clone(),
        RocksDbFactory.into(),
        gw_cfg.announce_address.clone(),
    )
    .into();
    let decoders = ModuleDecoderRegistry::from_iter([
        (
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            <Lightning as ServerModule>::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            <Mint as ServerModule>::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            <Wallet as ServerModule>::decoder(),
        ),
    ]);
    let module_gens = ModuleGenRegistry::from(vec![
        DynModuleGen::from(WalletGen),
        DynModuleGen::from(MintGen),
        DynModuleGen::from(LightningGen),
    ]);

    // Create gateway instance
    let task_group = TaskGroup::new();
    let gateway = LnGateway::new(
        gw_cfg,
        decoders,
        module_gens,
        ln_rpc,
        client_builder,
        tx,
        rx,
        task_group.clone(),
    )
    .await;

    if let Err(e) = gateway.run().await {
        task_group.shutdown_join_all(None).await?;

        error!("Gateway stopped with error: {}", e);
        return Err(e.into());
    }

    Ok(())
}
