use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fedimint_server::config::load_from_file;
use ln_gateway::ln::LnRpc;
use mint_client::{Client, GatewayClientConfig};
use rand::thread_rng;
use secp256k1::KeyPair;
use serde_json::json;
use tokio::io::{stdin, stdout};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::error;
use url::Url;

use ln_gateway::{
    cln::{build_cln_rpc, HtlcAccepted},
    rpc::GatewayRpcClient,
    BalancePayload, DepositAddressPayload, DepositPayload, GatewayRequest, GatewayRequestTrait,
    LnGateway, LnGatewayError, WithdrawPayload,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args();

    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{}", env!("GIT_HASH"));
            return Ok(());
        }
    }
    let (sender, receiver): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
        mpsc::channel(100);

    let (ln_rpc, bind_addr, workdir) = build_cln_rpc(sender).await.expect("Error building CLN RPC");
    let cfg_path = workdir.join("gateway.json");
    let db_path = workdir.join("gateway.db");

    let gw_client_cfg: GatewayClientConfig = load_from_file(&cfg_path);
    let db = fedimint_rocksdb::RocksDb::open(db_path)
        .expect("Error opening DB")
        .into();
    let ctx = secp256k1::Secp256k1::new();
    let federation_client = Arc::new(Client::new(gw_client_cfg, db, ctx));

    let gateway = LnGateway::new(federation_client, ln_rpc, sender, receiver, bind_addr);
    gateway.run().await.expect("gateway failed to run");
    Ok(())
}
