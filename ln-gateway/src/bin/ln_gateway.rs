use std::{path::PathBuf, sync::Arc};

use anyhow::Error;
use fedimint_server::config::load_from_file;
use ln_gateway::{cln, LnGateway};
use mint_client::{Client, GatewayClientConfig};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }

    let mut gateway = LnGateway::new();

    let workdir = gateway
        .register_ln_rpc(cln::build_cln_rpc)
        .await
        .expect("Failed to register cln rpc");

    let client =
        build_gateway_client(workdir).expect("Failed to build a gateway client with rocks db");

    gateway
        .register_federation(client)
        .await
        .expect("Failed to register federation");

    gateway.run().await.expect("gateway failed to run");
    Ok(())
}

/// Build a new federation gateway client with RocksDb and config at a given path
fn build_gateway_client(workdir: PathBuf) -> Result<Arc<Client<GatewayClientConfig>>, Error> {
    // Instantiate a gateway actor unique to this federation
    let cfg_path = workdir.join("gateway.json");
    let db_path = workdir.join("gateway.db");

    let client_cfg: GatewayClientConfig = load_from_file(&cfg_path);
    let db = fedimint_rocksdb::RocksDb::open(db_path)
        .expect("Error opening DB")
        .into();
    let ctx = secp256k1::Secp256k1::new();

    Ok(Arc::new(Client::new(client_cfg, db, ctx)))
}
