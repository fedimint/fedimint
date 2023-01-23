use cln_plugin::Error;
use fedimint_api::config::ModuleGenRegistry;
use fedimint_api::module::DynModuleGen;
use fedimint_api::{
    core::{
        LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
        LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    },
    module::registry::ModuleDecoderRegistry,
    task::TaskGroup,
};
use fedimint_server::modules::ln::LightningGen;
use fedimint_server::modules::mint::MintGen;
use fedimint_server::modules::wallet::WalletGen;
use fedimint_server::{
    config::load_from_file,
    modules::{
        ln::common::LightningDecoder, mint::common::MintDecoder, wallet::common::WalletDecoder,
    },
};
use ln_gateway::{
    client::{DynGatewayClientBuilder, RocksDbFactory, StandardGatewayClientBuilder},
    cln::{build_cln_rpc, ClnRpcRef},
    config::GatewayConfig,
    rpc::{GatewayRequest, GatewayRpcSender},
    LnGateway,
};
use tokio::sync::mpsc;
use tracing::error;
use tracing_subscriber::EnvFilter;

/// Fedimint gateway packaged as a CLN plugin
#[tokio::main]
#[deprecated(note = "Prefer to use `gateway-cln-extension` binary instead")]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

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
