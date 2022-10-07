use std::sync::Arc;

use anyhow::Error;
use fedimint_server::config::{load_from_file, ClientConfig};
use ln_gateway::{cln::ClnRpcFactory, ln::LnRpcRef, LnGateway};
use mint_client::{Client, GatewayClientConfig};
use rand::thread_rng;
use secp256k1::KeyPair;
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

    let rpc_factory = Arc::new(ClnRpcFactory::new());

    let mut gateway = LnGateway::new();
    let ln_ref = gateway
        .register_ln_rpc(rpc_factory.clone())
        .await
        .expect("Failed to register cln rpc");

    let client = build_federation_client(ln_ref.clone())?;

    gateway
        .register_federation(Arc::new(client))
        .await
        .expect("Failed to register federation");

    gateway.run().await.expect("gateway failed to run");
    Ok(())
}

/// Build a new federation client with RocksDb and config at a given path
fn build_federation_client(ln_ref: Arc<LnRpcRef>) -> Result<Client<GatewayClientConfig>, Error> {
    // Create a gateway client configuration
    let client_cfg_path = ln_ref.work_dir.join("client.json");
    let client_cfg: ClientConfig = load_from_file(&client_cfg_path);

    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let kp_fed = KeyPair::new(&ctx, &mut rng);

    let client_cfg = GatewayClientConfig {
        client_config: client_cfg,
        redeem_key: kp_fed,
        timelock_delta: 10,
        node_pub_key: ln_ref.pub_key,
        api: Url::parse(format!("http://{}", ln_ref.bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
    };

    // Create a database
    let db_path = ln_ref.work_dir.join("gateway.db");
    let db = fedimint_rocksdb::RocksDb::open(db_path)
        .expect("Error opening DB")
        .into();

    // Create context
    let ctx = secp256k1::Secp256k1::new();

    Ok(Client::new(client_cfg, db, ctx))
}
