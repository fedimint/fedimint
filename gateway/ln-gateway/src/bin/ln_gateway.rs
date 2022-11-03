use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use cln_plugin::Error;
use fedimint_api::config::ClientConfig;
use fedimint_server::config::load_from_file;
use ln_gateway::{
    client::{GatewayClientBuilder, RocksDbGatewayClientBuilder},
    cln::build_cln_rpc,
    config::GatewayConfig,
    ln::LnRpcRef,
    rpc::{GatewayRequest, GatewayRpcSender},
    LnGateway,
};
use mint_client::GatewayClientConfig;
use rand::thread_rng;
use secp256k1::{KeyPair, PublicKey};
use tokio::sync::mpsc;
use tracing::warn;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }
    let (tx, rx): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
        mpsc::channel(100);

    let sender = GatewayRpcSender::new(tx.clone());
    let LnRpcRef {
        ln_rpc,
        bind_addr,
        pub_key,
        work_dir,
    } = build_cln_rpc(sender).await?;

    let gw_cfg_path = work_dir.clone().join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path);

    // Create federation client builder
    let client_builder: GatewayClientBuilder =
        RocksDbGatewayClientBuilder::new(work_dir.clone()).into();

    // Create gateway instance
    let mut gateway = LnGateway::new(
        gw_cfg,
        ln_rpc,
        client_builder.clone(),
        tx,
        rx,
        bind_addr,
        pub_key,
    );

    // Build and register the default federation
    // TODO: Register default federation through gateway webserver api
    let client_cfg = build_federation_client_cfg(pub_key, bind_addr, work_dir)?;
    let default_fed = client_builder.build(client_cfg.clone())?;
    gateway.register_federation(Arc::new(default_fed)).await?;
    if let Err(e) = client_builder.save_config(client_cfg.clone()) {
        warn!(
            "Failed to save default federation client configuration: {}",
            e
        );
    }

    gateway.run().await.expect("gateway failed to run");
    Ok(())
}

/// Build a new federation client with RocksDb and config at a given path
fn build_federation_client_cfg(
    node_pub_key: PublicKey,
    bind_addr: SocketAddr,
    work_dir: PathBuf,
) -> Result<GatewayClientConfig, Error> {
    // Create a gateway client configuration
    let client_cfg_path = work_dir.join("client.json");
    let client_cfg: ClientConfig = load_from_file(&client_cfg_path);

    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let kp_fed = KeyPair::new(&ctx, &mut rng);

    Ok(GatewayClientConfig {
        client_config: client_cfg,
        redeem_key: kp_fed,
        timelock_delta: 10,
        node_pub_key,
        api: Url::parse(format!("http://{}", bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
    })
}
