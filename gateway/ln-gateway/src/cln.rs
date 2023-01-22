use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cln_plugin::{anyhow, options, Builder, Error, Plugin};
use cln_rpc::{model, ClnRpc, Request, Response};
use fedimint_api::Amount;
use fedimint_server::modules::ln::contracts::Preimage;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{stdin, stdout};
use tokio::sync::Mutex;
use tracing::{debug, error, instrument};

use crate::ReceivePaymentPayload;
use crate::{
    ln::{LightningError, LnRpc},
    rpc::GatewayRpcSender,
};

/// The core-lightning `htlc_accepted` event's `amount` field has a "msat" suffix
fn as_fedimint_amount<'de, D>(amount: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = String::deserialize(amount)?;
    Ok(Amount::from_msats(
        amount[0..amount.len() - 4].parse::<u64>().unwrap(),
    ))
}

// TODO: upstream these structs to cln-plugin
// See: https://github.com/ElementsProject/lightning/blob/master/doc/PLUGINS.md#htlc_accepted
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Htlc {
    pub short_channel_id: String,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub amount_msat: Amount,
    pub cltv_expiry: u32,
    pub cltv_expiry_relative: u32,
    pub payment_hash: bitcoin_hashes::sha256::Hash,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Onion {
    pub payload: String,
    pub short_channel_id: String,
    #[serde(deserialize_with = "as_fedimint_amount")]
    pub forward_msat: Amount,
    pub outgoing_cltv_value: u32,
    pub shared_secret: bitcoin_hashes::sha256::Hash,
    pub next_onion: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HtlcAccepted {
    pub htlc: Htlc,
    pub onion: Onion,
}

pub struct ClnRpcRef {
    // CLN RPC client
    pub ln_rpc: Arc<Mutex<ClnRpc>>,
    // Config directory
    pub work_dir: PathBuf,
}

#[async_trait]
impl LnRpc for Mutex<cln_rpc::ClnRpc> {
    #[instrument(name = "LnRpc::pubkey", skip(self))]
    async fn pubkey(&self) -> Result<secp256k1::PublicKey, LightningError> {
        let pubkey_result = self
            .lock()
            .await
            .call(Request::Getinfo(model::requests::GetinfoRequest {}))
            .await;

        match pubkey_result {
            Ok(Response::Getinfo(r)) => {
                let node_pubkey = r.id;
                Ok(secp256k1::PublicKey::from_slice(&node_pubkey.serialize()).unwrap())
            }
            Ok(_) => panic!("Core lightning sent wrong message"),
            Err(e) => panic!("Failed to fetch core-lightning node pubkey {:?}", e),
        }
    }

    #[instrument(name = "LnRpc::pay", skip(self))]
    async fn pay(
        &self,
        invoice: lightning_invoice::Invoice,
        max_delay: u64,
        max_fee_percent: f64,
    ) -> Result<Preimage, LightningError> {
        debug!("Attempting to pay invoice");

        let pay_result = self
            .lock()
            .await
            .call(cln_rpc::Request::Pay(model::PayRequest {
                bolt11: invoice.to_string(),
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: Some(max_fee_percent),
                retry_for: None,
                maxdelay: Some(max_delay as u16),
                exemptfee: None,
                localinvreqid: None,
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

/// BOLT 4: https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages
/// 16399 error code reports unknown payment details.
///
/// TODO: We should probably use a more specific error code based on htlc processing fail reason
fn htlc_processing_failure() -> serde_json::Value {
    serde_json::json!({
        "result": "fail",
        "failure_message": "1639"
    })
}

/// Handle core-lightning "htlc_accepted" events by attempting to buy this preimage from the federation
/// and completing the payment
async fn htlc_accepted_hook(
    plugin: Plugin<GatewayRpcSender>,
    value: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let htlc_accepted: HtlcAccepted = serde_json::from_value(value)?;

    // Filter and process intercepted HTLCs based on `short_channel_id` value.
    //
    // After https://github.com/fedimint/fedimint/pull/1180,
    // all HTLCs to Fedimint clients should have route hint with `short_channel_id = 0u64`,
    // unless the gateway is serving multiple federations.
    if htlc_accepted.onion.short_channel_id == "0x0x0" {
        let preimage = match plugin
            .state()
            .send(ReceivePaymentPayload { htlc_accepted })
            .await
        {
            Ok(preimage) => preimage,
            Err(_) => return Ok(htlc_processing_failure()),
        };

        let pk = preimage.to_public_key()?;
        Ok(serde_json::json!({
          "result": "resolve",
          "payment_key": pk.to_string(),
        }))
    } else {
        // HTLC is not relevant to fedimint
        Ok(serde_json::json!({
            "result": "continue",
        }))
    }
}

pub async fn build_cln_rpc(sender: GatewayRpcSender) -> Result<ClnRpcRef, Error> {
    if let Some(plugin) = Builder::new(stdin(), stdout())
        .option(options::ConfigOption::new(
            "fedimint-cfg",
            // FIXME: cln_plugin doesn't support parameters without defaults
            options::Value::String("default-dont-use".into()),
            "fedimint config directory",
        ))
        .hook("htlc_accepted", |plugin, value| async move {
            // This callback needs to be `Sync`, so we use tokio::spawn
            let handle = tokio::spawn(async move {
                // FIXME: Test this potential fix for Issue 1018: Gateway channel force closures
                //
                // Timeout processing of intecepted HTLC after 30 seconds
                // If the HTLC is not resolved, we continue and forward it to the next hop
                tokio::time::timeout(Duration::from_secs(30), htlc_accepted_hook(plugin, value))
                    .await
                    .unwrap_or_else(|_| Err(anyhow!("htlc_accepted timeout")))
                    .or_else(|e| {
                        error!("htlc_accepted error {:?}", e);
                        Ok(htlc_processing_failure())
                    })
            });
            handle.await?
        })
        .dynamic() // Allow reloading the plugin
        .start(sender)
        .await?
    {
        let work_dir = match plugin.option("fedimint-cfg") {
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

        let config = plugin.configuration();
        let cln_rpc_socket = PathBuf::from(config.lightning_dir).join(config.rpc_file);
        let cln_rpc = ClnRpc::new(cln_rpc_socket)
            .await
            .expect("connect to ln_socket");

        Ok(ClnRpcRef {
            ln_rpc: Arc::new(Mutex::new(cln_rpc)),
            work_dir,
        })
    } else {
        Err(anyhow!("Failed to build cln rpc plugin!"))
    }
}
