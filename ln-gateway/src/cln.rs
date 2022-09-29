use async_trait::async_trait;
use cln_plugin::{anyhow, options, Builder, Error, Plugin};
use cln_rpc::{model::PayRequest, ClnRpc};
use fedimint_api::Amount;
use fedimint_server::config::load_from_file;
use fedimint_server::modules::ln::contracts::Preimage;
use mint_client::GatewayClientConfig;
use rand::thread_rng;
use secp256k1::KeyPair;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{stdin, stdout};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, instrument};
use url::Url;

use crate::{
    ln::{LightningError, LnRpc},
    rpc::GatewayRpcSender,
    BalancePayload, DepositAddressPayload, DepositPayload, GatewayRequest, WithdrawPayload,
};

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat" suffix
fn as_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    Ok(Amount::from_msat(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}

// TODO: upstream these structs to cln-plugin
#[derive(Clone, Deserialize, Debug)]
pub struct Htlc {
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub amount: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Onion {
    pub payload: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub short_channel_id: String,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_amount: Amount,
    pub outgoing_cltv_value: u32,
    pub shared_secret: bitcoin_hashes::sha256::Hash,
    pub next_onion: String,
}

#[derive(Clone, Deserialize, Debug)]
pub struct HtlcAccepted {
    pub htlc: Htlc,
    pub onion: Onion,
}

#[async_trait]
impl LnRpc for Mutex<cln_rpc::ClnRpc> {
    #[instrument(name = "LnRpc::pay", skip(self))]
    async fn pay(
        &self,
        invoice: &str,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        debug!("Attempting to pay invoice");

        let pay_result = self
            .lock()
            .await
            .call(cln_rpc::Request::Pay(PayRequest {
                bolt11: invoice.to_string(),
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: Some(max_fee_percent),
                retry_for: None,
                maxdelay: Some(max_delay as u16),
                exemptfee: None,
                localofferid: None,
                exclude: None,
                maxfee: None,
                description: None,
            }))
            .await;

        match pay_result {
            Ok(cln_rpc::Response::Pay(pay_success)) => {
                debug!("Successfully paid invoice");
                let slice: [u8; 32] = pay_success.payment_preimage.to_vec().try_into().unwrap();
                Ok(Preimage(slice))
            }
            Ok(_) => unreachable!("unexpected response from C-lightning"),
            Err(cln_rpc::RpcError { code, message }) => {
                if let Some(code) = code {
                    debug!(%code, %message, "c-lightning pay returned error");
                } else {
                    debug!(%message, "c-lightning pay returned error");
                }
                Err(LightningError(code))
            }
        }
    }
}

type PluginState = GatewayRpcSender;

/// Handle core-lightning "htlc_accepted" events by attempting to buy this preimage from the federation
/// and completing the payment
async fn htlc_accepted_hook(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let htlc_accepted: HtlcAccepted = serde_json::from_value(value)?;
    let preimage = plugin.state().send(htlc_accepted).await?;
    let pk = preimage.to_public_key()?;
    Ok(serde_json::json!({
      "result": "resolve",
      "payment_key": pk.to_string(),
    }))
}

async fn balance_rpc(
    plugin: Plugin<PluginState>,
    _: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let amount = plugin.state().send(BalancePayload {}).await?;
    Ok(json!({ "balance_msat": amount.milli_sat }))
}

async fn address(
    plugin: Plugin<PluginState>,
    _: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let address = plugin.state().send(DepositAddressPayload {}).await?;
    Ok(json!({ "address": address }))
}

async fn deposit_rpc(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let deposit: DepositPayload = serde_json::from_value(value)?;
    let txid = plugin.state().send(deposit).await?;
    Ok(json!({ "fedimint_txid": txid.to_string() }))
}

async fn withdraw_rpc(
    plugin: Plugin<PluginState>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let withdraw: WithdrawPayload = serde_json::from_value(value)?;
    let txid = plugin.state().send(withdraw).await?;
    Ok(json!({ "fedimint_txid": txid.to_string() }))
}

/// Start the core-lightning plugin and register it in an LnRpc
/// This process generates and writes rpc configs to a known location
///
/// Returns
///
/// * CLN LnRpc
/// * The Ln Rpc bind address
/// * Working directory hosting the rpc config path
pub async fn build_cln_rpc(
    sender: mpsc::Sender<GatewayRequest>,
) -> Result<(Arc<dyn LnRpc>, SocketAddr, PathBuf), Error> {
    let state = GatewayRpcSender::new(sender.clone());

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
        Ok((Arc::new(Mutex::new(ln_client)), bind_addr, workdir))
    } else {
        Err(anyhow!("Failed to build cln rpc!"))
    }
}

/// Create [`gateway.json`] config files
async fn generate_config(workdir: &Path, ln_client: &mut ClnRpc, bind_addr: &SocketAddr) {
    let client_cfg_path = workdir.join("client.json");
    let client_cfg: fedimint_server::config::ClientConfig = load_from_file(&client_cfg_path);

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
