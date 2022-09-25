use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cln_plugin::{options, Builder, Error, Plugin};
use cln_rpc::ClnRpc;
use mint_client::{Client, GatewayClientConfig};
use rand::thread_rng;
use secp256k1::KeyPair;
use serde_json::json;
use tokio::io::{stdin, stdout};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::error;
use url::Url;

use fedimint::config::load_from_file;
use ln_gateway::{
    cln::HtlcAccepted, BalancePayload, DepositAddressPayload, DepositPayload, GatewayRequest,
    GatewayRequestTrait, LnGateway, LnGatewayError, WithdrawPayload,
};

type PluginState = Arc<Mutex<mpsc::Sender<GatewayRequest>>>;

/// Create [`gateway.json`] config files
async fn generate_config(workdir: &Path, ln_client: &mut ClnRpc, bind_addr: &SocketAddr) {
    let client_cfg_path = workdir.join("client.json");
    let client_cfg: fedimint::config::ClientConfig = load_from_file(&client_cfg_path);

    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let kp_fed = KeyPair::new(&ctx, &mut rng);

    let node_pub_key_bytes = match ln_client
        .call(cln_rpc::Request::Getinfo(
            cln_rpc::model::requests::GetinfoRequest {},
        ))
        .await
    {
        Ok(cln_rpc::Response::Getinfo(r)) => r.id,
        Ok(_) => panic!("Core lightning sent wrong message"),
        Err(e) => panic!("Failed to fetch core-lightning node pubkey {:?}", e),
    };
    let node_pub_key = secp256k1::PublicKey::from_slice(&node_pub_key_bytes.to_vec()).unwrap();

    // Write gateway config
    let gateway_cfg = GatewayClientConfig {
        client_config: client_cfg.clone(),
        redeem_key: kp_fed,
        timelock_delta: 10,
        node_pub_key,
        api: Url::parse(format!("http://{}", bind_addr).as_str())
            .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
    };
    let gw_cfg_file_path: PathBuf = workdir.join("gateway.json");
    let gw_cfg_file = std::fs::File::create(gw_cfg_file_path).expect("Could not create cfg file");
    serde_json::to_writer_pretty(gw_cfg_file, &gateway_cfg).unwrap();
}

/// Loads configs if they exist, generates them if not
/// Initializes [`LnGateway`] and runs it's main event loop
async fn initialize_gateway(
    plugin: &Plugin<PluginState>,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
) -> LnGateway {
    let workdir = match plugin.option("fedimint-cfg") {
        Some(options::Value::String(workdir)) => {
            // FIXME: cln_plugin doesn't yet support optional parameters
            if &workdir == "default-dont-use" {
                panic!("fedimint-cfg option missing")
            } else {
                PathBuf::from(workdir)
            }
        }
        _ => unreachable!(),
    };
    let host = match plugin.option("fedimint-host") {
        Some(options::Value::String(host)) => host,
        _ => unreachable!(),
    };
    let port = match plugin.option("fedimint-port") {
        Some(options::Value::String(port)) => port,
        _ => unreachable!(),
    };
    let bind_addr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid gateway bind address");

    // If no config exists, try to generate one
    let cfg_path = workdir.join("gateway.json");
    let config = plugin.configuration();
    let cln_rpc_socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);
    let mut ln_client = ClnRpc::new(cln_rpc_socket)
        .await
        .expect("connect to ln_socket");
    if !Path::new(&cfg_path).is_file() {
        generate_config(&workdir, &mut ln_client, &bind_addr).await;
    }

    // Run the gateway
    let db_path = workdir.join("gateway.db");
    let gw_client_cfg: GatewayClientConfig = load_from_file(&cfg_path);
    let db = fedimint_rocksdb::RocksDb::open(db_path)
        .expect("Error opening DB")
        .into_dyn();
    let ctx = secp256k1::Secp256k1::new();
    let federation_client = Arc::new(Client::new(gw_client_cfg, db, ctx));
    let ln_client = Box::new(Mutex::new(ln_client));

    LnGateway::new(federation_client, ln_client, sender, receiver, bind_addr)
}

/// Send message to LnGateway over channel and receive response over onshot channel
async fn gw_rpc<R>(plugin: Plugin<PluginState>, message: R) -> Result<R::Response, Error>
where
    R: GatewayRequestTrait,
{
    let (sender, receiver) = oneshot::channel::<Result<R::Response, LnGatewayError>>();
    let gw_sender = { plugin.state().lock().await.clone() };
    let msg = message.to_enum(sender);
    gw_sender
        .send(msg)
        .await
        .expect("failed to send over channel");
    Ok(receiver.await.expect("Failed to send over channel")?)
}

/// Handle core-lightning "htlc_accepted" events by attempting to buy this preimage from the federation
/// and completing the payment
async fn htlc_accepted_hook(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let htlc_accepted: HtlcAccepted = serde_json::from_value(value)?;
    let preimage = gw_rpc(plugin, htlc_accepted).await?;
    Ok(serde_json::json!({
      "result": "resolve",
      "payment_key": preimage,
    }))
}

async fn balance_rpc(
    plugin: Plugin<PluginState>,
    _: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let amount = gw_rpc(plugin, BalancePayload {}).await?;
    Ok(json!({ "balance_msat": amount.milli_sat }))
}

async fn address(
    plugin: Plugin<PluginState>,
    _: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let address = gw_rpc(plugin, DepositAddressPayload {}).await?;
    Ok(json!({ "address": address }))
}

async fn deposit_rpc(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let deposit: DepositPayload = serde_json::from_value(value)?;
    let txid = gw_rpc(plugin, deposit).await?;
    Ok(json!({ "fedimint_txid": txid.to_string() }))
}

async fn withdraw_rpc(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let withdraw: WithdrawPayload = serde_json::from_value(value)?;
    let txid = gw_rpc(plugin, withdraw).await?;
    Ok(json!({ "fedimint_txid": txid.to_string() }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (sender, receiver): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
        mpsc::channel(100);
    let state = Arc::new(Mutex::new(sender.clone()));

    // Register this plugin with core-lightning
    if let Some(plugin) = Builder::new(state, stdin(), stdout())
        .option(options::ConfigOption::new(
            "fedimint-cfg",
            // FIXME: cln_plugin doesn't support parameters without defaults
            options::Value::String("default-dont-use".into()),
            "fedimint config directory",
        ))
        .option(options::ConfigOption::new(
            "fedimint-host",
            options::Value::String("127.0.0.1".into()),
            "gateway hostname",
        ))
        .option(options::ConfigOption::new(
            "fedimint-port",
            options::Value::String("8080".into()),
            "gateway port",
        ))
        .rpcmethod("gw-balance", "Display ecash token balance", balance_rpc)
        .rpcmethod(
            "gw-deposit",
            "Deposit into federation. Args: <txoutproof> <bitcoin-transaction>",
            deposit_rpc,
        )
        .rpcmethod(
            "gw-withdraw",
            "Withdraw from federation. Args: <address> <sats>",
            withdraw_rpc,
        )
        .rpcmethod("gw-address", "Generate deposit address", address)
        .hook("htlc_accepted", |plugin, value| async move {
            // This callback needs to be `Sync`, so we use tokio::spawn
            let handle = tokio::spawn(async move {
                htlc_accepted_hook(plugin, value).await.or_else(|e| {
                    error!("htlc_accepted error {:?}", e);
                    // cln_plugin doesn't handle errors very well ... tell it to proceed normally
                    Ok(json!({ "result": "continue" }))
                })
            });
            handle.await?
        })
        .dynamic() // Allow reloading the plugin
        .start()
        .await?
    {
        let mut gateway = initialize_gateway(&plugin, sender, receiver).await;
        gateway.run().await.expect("gateway failed to run");
        Ok(())
    } else {
        Ok(())
    }
}
