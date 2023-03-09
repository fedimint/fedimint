use std::collections::HashSet;
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use cln_plugin::{options, Builder, Plugin};
use fedimint_core::task::TaskGroup;
use ln_gateway::cln::HtlcAccepted;
use ln_gateway::rpc::rpc_client::RpcClient;
use ln_gateway::rpc::HtlcPayload;
use reqwest::Url;
use serde_json::json;
use tokio::io::{stdin, stdout};
use tokio::sync::Mutex;
use tracing::{debug, info};

#[derive(Parser)]
pub struct Args {
    /// Gateway HTTP RPC server listen address
    #[arg(long = "gateway-api", env = "FM_GATEWAY_API_ADDR")]
    pub gateway_api: Url,

    /// Gateway HTTP RPC server password
    #[arg(long = "gateway-password", env = "FM_GATEWAY_PASSWORD")]
    pub gateway_password: String,
}

#[derive(Clone)]
struct HtlcInterceptor {
    gateway_rpc: RpcClient,
    gateway_password: String,
    scids: Arc<Mutex<HashSet<u64>>>,
}

impl HtlcInterceptor {
    pub fn new(gateway_api: Url, gateway_password: String) -> Self {
        Self {
            gateway_rpc: RpcClient::new(gateway_api),
            gateway_password,
            scids: Arc::new(Mutex::new(HashSet::new())),
        }
    }
    async fn intercept_htlc(&self, htlc_accepted: HtlcAccepted) -> serde_json::Value {
        // FIXME: this payload is weird ... why don't I just send HtlcAccepted?
        info!("HtlcInterceptor.intercept_htlc()");
        let htlc_payload = HtlcPayload { htlc_accepted };
        let resp = self
            .gateway_rpc
            // FIXME: clone
            .intercept_htlc(self.gateway_password.clone(), htlc_payload)
            .await
            .expect("intercept_htlc blew up"); // FIXME: don't unwrap
        info!("resp {:?}", resp);
        resp.json()
            .await
            .expect("intercept_htlc didn't return json")
        // self.gateway_rpc
        //     // FIXME: clone
        //     .intercept_htlc(self.gateway_password.clone(), htlc_payload)
        //     .await
        //     .expect("intercept_htlc blew up") // FIXME: don't unwrap
        //     .json()
        //     .await
        //     .expect("intercept_htlc didn't return json")
    }
}

// Note: Once this binary is stable, we should be able to remove current
// 'ln_gateway' Use CLN_PLUGIN_LOG=<log-level> to enable debug logging from
// within cln-plugin
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Parse configurations or read from
    let Args {
        gateway_api,
        gateway_password,
    } = Args::try_parse()?;
    debug!("Starting fedimint_cln with gateway API: {}", gateway_api);

    if let Some(plugin) = Builder::new(stdin(), stdout())
        .hook(
            "htlc_accepted",
            |plugin: Plugin<HtlcInterceptor>, value: serde_json::Value| async move {
                // This callback needs to be `Sync`, so we use tokio::spawn
                info!("observed HTLC {:?}", value);
                let handle = tokio::spawn(async move {
                    // Handle core-lightning "htlc_accepted" events
                    // by passing the HTLC to the interceptor in the plugin state
                    let htlc_accepted: HtlcAccepted = serde_json::from_value(value)?;
                    Ok(plugin.state().intercept_htlc(htlc_accepted).await)
                });
                handle.await?
            },
        )
        .rpcmethod(
            "registerscid",
            "Subscribe to HTLC which match a given SCID. This is used to filter HTLCs in the plugin",
            |plugin: Plugin<HtlcInterceptor>, value: serde_json::Value| async move {
                info!("register_scid {:?}", value);
                let mut scids = plugin.state().scids.lock().await;
                let scid: u64 = match value[0].as_u64() {
                    Some(scid) => scid,
                    None => bail!("Invalid SCID")
                };
                scids.insert(scid);
                Ok(json!(*scids))
            },
        )
        // Shutdown the plugin when lightningd is shutting down or when the plugin is stopped
        // via `plugin stop` command. There's a chance that the subscription is never called in
        // case lightningd crashes or aborts.
        // For details, see documentation for `shutdown` event notification:
        // https://lightning.readthedocs.io/PLUGINS.html?highlight=shutdown#shutdown
        .subscribe(
            "shutdown",
            |plugin: Plugin<HtlcInterceptor>, _: serde_json::Value| async move {
                info!("Received \"shutdown\" notification from lightningd ... requesting cln_plugin shutdown");
                plugin.shutdown()
            },
        )
        .dynamic() // Allow reloading the plugin
        .start(HtlcInterceptor::new(gateway_api, gateway_password))
        .await? {
            // handle shutdown
            let _ = plugin.join().await;
            info!("Plugin stopped");
        };

    Ok(())
}
