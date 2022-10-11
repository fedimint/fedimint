use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use cln_plugin::Error;
use fedimint_server::config::{load_from_file, ClientConfig};
use ln_gateway::{
    cln::build_cln_rpc, ln::LnRpcRef, rpc::GatewayRpcSender, GatewayRequest, LnGateway,
};
use mint_client::{Client, GatewayClientConfig};
use rand::thread_rng;
use secp256k1::{KeyPair, PublicKey};
use tokio::sync::mpsc;
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

    let federation_client = build_federation_client(pub_key, bind_addr, work_dir)?;
    let mut gateway = LnGateway::new(Arc::new(federation_client), ln_rpc, tx, rx, bind_addr);

    gateway.run().await.expect("gateway failed to run");
    Ok(())
}

/// Build a new federation client with RocksDb and config at a given path
fn build_federation_client(
    node_pub_key: PublicKey,
    bind_addr: SocketAddr,
    work_dir: PathBuf,
) -> Result<Client<GatewayClientConfig>, Error> {
    // Create a gateway client configuration
    let client_cfg_path = work_dir.join("client.json");
    let client_cfg: ClientConfig = load_from_file(&client_cfg_path);

    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let kp_fed = KeyPair::new(&ctx, &mut rng);

    let client_cfg = GatewayClientConfig {
        client_config: client_cfg,
        redeem_key: kp_fed,
        timelock_delta: 10,
        node_pub_key,
        api: Url::parse(format!("http://{}", bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
    };

    // Create a database
    let db_path = work_dir.join("gateway.db");
    let db = fedimint_rocksdb::RocksDb::open(db_path)
        .expect("Error opening DB")
        .into();

    // Create context
    let ctx = secp256k1::Secp256k1::new();

    Ok(Client::new(client_cfg, db, ctx))
}
