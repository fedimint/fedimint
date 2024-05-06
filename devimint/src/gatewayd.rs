use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use fedimint_core::util::retry;
use ln_gateway::lightning::ChannelInfo;
use ln_gateway::rpc::V1_API_ENDPOINT;
use tracing::info;

use crate::cmd;
use crate::envs::{FM_GATEWAY_API_ADDR_ENV, FM_GATEWAY_DATA_DIR_ENV, FM_GATEWAY_LISTEN_ADDR_ENV};
use crate::external::{Bitcoind, LightningNode};
use crate::federation::Federation;
use crate::util::{poll, Command, ProcessHandle, ProcessManager};
use crate::vars::utf8;

#[derive(Clone)]
pub struct Gatewayd {
    pub(crate) _process: ProcessHandle,
    pub ln: Option<LightningNode>,
    pub(crate) addr: String,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: LightningNode) -> Result<Self> {
        let ln_name = ln.name();
        let test_dir = &process_mgr.globals.FM_TEST_DIR;
        let port = match ln {
            LightningNode::Cln(_) => process_mgr.globals.FM_PORT_GW_CLN,
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_GW_LND,
        };
        let addr = format!("http://127.0.0.1:{port}/{V1_API_ENDPOINT}");
        let gateway_env: HashMap<String, String> = HashMap::from_iter([
            (
                FM_GATEWAY_DATA_DIR_ENV.to_owned(),
                format!("{}/{ln_name}", utf8(test_dir)),
            ),
            (
                FM_GATEWAY_LISTEN_ADDR_ENV.to_owned(),
                format!("127.0.0.1:{port}"),
            ),
            (FM_GATEWAY_API_ADDR_ENV.to_owned(), addr.clone()),
        ]);
        let process = process_mgr
            .spawn_daemon(
                &format!("gatewayd-{ln_name}"),
                cmd!(crate::util::Gatewayd, ln_name).envs(gateway_env),
            )
            .await?;

        let gatewayd = Self {
            ln: Some(ln),
            _process: process,
            addr,
        };
        poll(
            "waiting for gateway to be ready to respond to rpc",
            || async { gatewayd.gateway_id().await.map_err(ControlFlow::Continue) },
        )
        .await?;
        Ok(gatewayd)
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = Some(ln_node);
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        info!("Stopping lightning node");
        match self.ln.take() {
            Some(LightningNode::Lnd(lnd)) => lnd.terminate().await,
            Some(LightningNode::Cln(cln)) => cln.terminate().await,
            None => Err(anyhow::anyhow!(
                "Cannot stop an already stopped Lightning Node"
            )),
        }
    }

    /// Restarts the gateway using the provided `bin_path`, which is useful for
    /// testing upgrades.
    pub async fn restart_with_bin(
        &mut self,
        process_mgr: &ProcessManager,
        bin_path: &PathBuf,
    ) -> Result<()> {
        self._process.terminate().await?;
        std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", bin_path);
        let ln = self
            .ln
            .as_ref()
            .expect("gateway already had an associated ln node")
            .clone();
        let new_gw = Self::new(process_mgr, ln).await?;
        self._process = new_gw._process;
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        info!("upgraded gatewayd to version: {}", gatewayd_version);
        Ok(())
    }

    pub async fn cmd(&self) -> Command {
        cmd!(
            crate::util::get_gateway_cli_path(),
            "--rpcpassword=theresnosecondbest",
            "-a",
            &self.addr
        )
    }

    pub async fn get_info(&self) -> Result<serde_json::Value> {
        retry(
            "Getting {} gateway info via gateway-cli info",
            fedimint_core::util::FibonacciBackoff::default()
                .with_min_delay(Duration::from_millis(200))
                .with_max_delay(Duration::from_secs(5))
                .with_max_times(10),
            || async { cmd!(self, "info").out_json().await },
        )
        .await
        .context("Getting gateway info via gateway-cli info")
    }

    pub async fn gateway_id(&self) -> Result<String> {
        let info = self.get_info().await?;
        let gateway_id = info["gateway_id"]
            .as_str()
            .context("gateway_id must be a string")?
            .to_owned();
        Ok(gateway_id)
    }

    pub async fn lightning_pubkey(&self) -> Result<String> {
        let info = self.get_info().await?;
        let gateway_id = info["lightning_pub_key"]
            .as_str()
            .context("lightning_pub_key must be a string")?
            .to_owned();
        Ok(gateway_id)
    }

    pub async fn connect_fed(&self, fed: &Federation) -> Result<()> {
        let invite_code = fed.invite_code()?;
        poll("gateway connect-fed", || async {
            cmd!(self, "connect-fed", invite_code.clone())
                .run()
                .await
                .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    pub async fn get_pegin_addr(&self, fed_id: &str) -> Result<String> {
        Ok(cmd!(self, "address", "--federation-id={fed_id}")
            .out_json()
            .await?
            .as_str()
            .context("address must be a string")?
            .to_owned())
    }

    pub async fn connect_to_peer(&self, pubkey: String, host: String) -> Result<()> {
        cmd!(
            self,
            "lightning",
            "connect-to-peer",
            "--pubkey",
            pubkey,
            "--host",
            host
        )
        .run()
        .await?;
        Ok(())
    }

    pub async fn get_funding_address(&self) -> Result<String> {
        let address = cmd!(self, "lightning", "get-funding-address")
            .out_string()
            .await?;
        Ok(address)
    }

    pub async fn open_channel(
        &self,
        pubkey: String,
        channel_size_sats: u64,
        push_amount_sats: Option<u64>,
    ) -> Result<()> {
        cmd!(
            self,
            "lightning",
            "open-channel",
            "--pubkey",
            pubkey,
            "--channel-size-sats",
            channel_size_sats,
            "--push-amount-sats",
            push_amount_sats.unwrap_or(0)
        )
        .run()
        .await?;
        Ok(())
    }

    pub async fn list_active_channels(&self) -> Result<Vec<ChannelInfo>> {
        let channels = cmd!(self, "lightning", "list-active-channels")
            .out_json()
            .await?;
        let channels = channels
            .as_array()
            .context("channels must be an array")?
            .iter()
            .map(|channel| {
                let remote_pubkey = channel["remote_pubkey"]
                    .as_str()
                    .context("remote_pubkey must be a string")?
                    .to_owned();
                let channel_size_sats = channel["channel_size_sats"]
                    .as_u64()
                    .context("channel_size_sats must be a u64")?;
                let outbound_liquidity_sats = channel["outbound_liquidity_sats"]
                    .as_u64()
                    .context("outbound_liquidity_sats must be a u64")?;
                let inbound_liquidity_sats = channel["inbound_liquidity_sats"]
                    .as_u64()
                    .context("inbound_liquidity_sats must be a u64")?;
                let short_channel_id = channel["short_channel_id"]
                    .as_u64()
                    .context("short_channel_id must be a u64")?;
                let channel_point_txid = channel["channel_point_txid"]
                    .as_str()
                    .context("channel_point_txid must be a string")?
                    .to_owned();
                let channel_point_output_index = channel["channel_point_output_index"]
                    .as_u64()
                    .context("channel_point_output_index must be a u32")?
                    .try_into()
                    .context("channel_point_output_index must be a u32")?;
                Ok(ChannelInfo {
                    remote_pubkey,
                    channel_size_sats,
                    outbound_liquidity_sats,
                    inbound_liquidity_sats,
                    short_channel_id,
                    channel_point_txid,
                    channel_point_output_index,
                })
            })
            .collect::<Result<Vec<ChannelInfo>>>()?;
        Ok(channels)
    }

    pub async fn wait_for_chain_sync(&self, bitcoind: &Bitcoind) -> Result<()> {
        poll("lightning node block processing", || async {
            let block_height = bitcoind
                .get_block_count()
                .await
                .map_err(ControlFlow::Continue)?
                - 1;
            cmd!(
                self,
                "lightning",
                "wait-for-chain-sync",
                "--block-height",
                block_height
            )
            .run()
            .await
            .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await?;
        Ok(())
    }
}
