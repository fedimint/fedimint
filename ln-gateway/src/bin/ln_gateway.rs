use std::path::{Path, PathBuf};
use std::sync::Arc;

use cln_plugin::{options, Builder, Error, Plugin};
use cln_rpc::ClnRpc;
use rand::thread_rng;
use secp256k1::KeyPair;
use serde_json::json;
use tokio::io::{stdin, stdout};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::error;

use ln_gateway::{cln::HtlcAccepted, GatewayRequest, LnGateway, LnGatewayError};
use minimint::config::load_from_file;
use minimint::modules::ln::contracts::incoming::Preimage;
use mint_client::clients::gateway::{GatewayClient, GatewayClientConfig};
use mint_client::ln::gateway::LightningGateway;
use mint_client::ClientAndGatewayConfig;

type PluginState = Arc<Mutex<mpsc::Sender<GatewayRequest>>>;

/// Create [`gateway.json`] and [`client.json`] config files
async fn generate_config(workdir: &Path, ln_client: &mut ClnRpc) {
    let federation_client_cfg_path = workdir.join("federation_client.json");
    let federation_client_cfg: minimint::config::ClientConfig =
        load_from_file(&federation_client_cfg_path);

    let mut rng = thread_rng();
    let ctx = secp256k1::Secp256k1::new();
    let kp_fed = KeyPair::new(&ctx, &mut rng);

    let gateway_cfg = GatewayClientConfig {
        common: federation_client_cfg.clone(),
        redeem_key: kp_fed,
        timelock_delta: 10,
    };

    let gw_cfg_file_path: PathBuf = workdir.join("gateway.json");
    let gw_cfg_file = std::fs::File::create(gw_cfg_file_path).expect("Could not create cfg file");
    serde_json::to_writer_pretty(gw_cfg_file, &gateway_cfg).unwrap();

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

    let client_cfg = ClientAndGatewayConfig {
        client: federation_client_cfg,
        gateway: LightningGateway {
            mint_pub_key: kp_fed.public_key(),
            node_pub_key,
            api: "http://127.0.0.1:8080".to_string(),
        },
    };

    let client_cfg_file_path: PathBuf = workdir.join("client.json");
    let client_cfg_file =
        std::fs::File::create(client_cfg_file_path).expect("Could not create cfg file");
    serde_json::to_writer_pretty(client_cfg_file, &client_cfg).unwrap();
}

/// Loads configs if they exist, generates them if not
/// Initializes [`LnGateway`] and runs it's main event loop
async fn initialize_gateway(
    plugin: &Plugin<PluginState>,
    sender: mpsc::Sender<GatewayRequest>,
    receiver: mpsc::Receiver<GatewayRequest>,
) -> LnGateway {
    let workdir = match plugin.option("minimint-cfg") {
        Some(options::Value::String(workdir)) => {
            // FIXME: cln_plugin doesn't yet support optional parameters
            if &workdir == "default-dont-use" {
                panic!("minimint-cfg option missing")
            } else {
                PathBuf::from(workdir)
            }
        }
        _ => unreachable!(),
    };

    // If no config exists, try to generate one
    let cfg_path = workdir.join("gateway.json");
    let config = plugin.configuration();
    let cln_rpc_socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);
    let mut ln_client = ClnRpc::new(cln_rpc_socket)
        .await
        .expect("connect to ln_socket");
    if !Path::new(&cfg_path).is_file() {
        generate_config(&workdir, &mut ln_client).await;
    }

    // Run the gateway
    let db_path = workdir.join("gateway.db");
    let gw_client_cfg: GatewayClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();
    let federation_client = Arc::new(GatewayClient::new(gw_client_cfg, Box::new(db)).await);
    let ln_client = Box::new(Mutex::new(ln_client));

    LnGateway::new(federation_client, ln_client, sender, receiver)
}

/// Handle core-lightning "htlc_accepted" events by attempting to buy this preimage from the federation
/// and completing the payment
async fn htlc_accepted_handler(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let (htlc_sender, htlc_receiver) = oneshot::channel::<Result<Preimage, LnGatewayError>>();
    let gw_sender = { plugin.state().lock().await.clone() };
    let htlc_accepted: HtlcAccepted = serde_json::from_value(value)?;
    gw_sender
        .send(GatewayRequest::HtlcAccepted(htlc_accepted, htlc_sender))
        .await
        .expect("failed to send over channel");
    let preimage = htlc_receiver.await.unwrap()?;

    Ok(serde_json::json!({
      "result": "resolve",
      "payment_key": preimage,
    }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (sender, receiver): (mpsc::Sender<GatewayRequest>, mpsc::Receiver<GatewayRequest>) =
        mpsc::channel(100);
    let state = Arc::new(Mutex::new(sender.clone()));

    // Register this plugin with core-lightning
    if let Some(plugin) = Builder::new(state, stdin(), stdout())
        .option(options::ConfigOption::new(
            "minimint-cfg",
            // FIXME: cln_plugin doesn't support parameters without defaults
            options::Value::String("default-dont-use".into()),
            "minimint config directory",
        ))
        .hook("htlc_accepted", |plugin, value| async move {
            // This callback needs to be `Sync`, so we use tokio::spawn
            let handle = tokio::spawn(async move {
                htlc_accepted_handler(plugin, value).await.or_else(|e| {
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
