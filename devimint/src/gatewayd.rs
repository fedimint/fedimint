use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::{Context, Result};
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::{backoff_util, retry};
use fedimint_testing::gateway::LightningNodeType;
use ln_gateway::lightning::ChannelInfo;
use ln_gateway::rpc::{MnemonicResponse, V1_API_ENDPOINT};
use tracing::info;

use crate::envs::{FM_GATEWAY_API_ADDR_ENV, FM_GATEWAY_DATA_DIR_ENV, FM_GATEWAY_LISTEN_ADDR_ENV};
use crate::external::{Bitcoind, LightningNode};
use crate::federation::Federation;
use crate::util::{poll, Command, ProcessHandle, ProcessManager};
use crate::vars::utf8;
use crate::version_constants::VERSION_0_5_0_ALPHA;
use crate::{cmd, Lightningd};

#[derive(Clone)]
pub struct Gatewayd {
    pub(crate) process: ProcessHandle,
    pub ln: Option<LightningNode>,
    pub addr: String,
    pub(crate) lightning_node_addr: String,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: LightningNode) -> Result<Self> {
        let ln_name = ln.name();
        let test_dir = &process_mgr.globals.FM_TEST_DIR;

        let port = match ln {
            LightningNode::Cln(_) => process_mgr.globals.FM_PORT_GW_CLN,
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_GW_LND,
            LightningNode::Ldk => process_mgr.globals.FM_PORT_GW_LDK,
        };
        let addr = format!("http://127.0.0.1:{port}/{V1_API_ENDPOINT}");

        let lightning_node_port = match ln {
            LightningNode::Cln(_) => process_mgr.globals.FM_PORT_CLN,
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_LND_LISTEN,
            LightningNode::Ldk => process_mgr.globals.FM_PORT_LDK,
        };
        let lightning_node_addr = format!("127.0.0.1:{lightning_node_port}");

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
            process,
            addr,
            lightning_node_addr,
        };
        poll(
            "waiting for gateway to be ready to respond to rpc",
            || async { gatewayd.gateway_id().await.map_err(ControlFlow::Continue) },
        )
        .await?;
        Ok(gatewayd)
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = Some(ln_node);
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        info!("Stopping lightning node");
        match self.ln.take() {
            Some(LightningNode::Lnd(lnd)) => lnd.terminate().await,
            Some(LightningNode::Cln(cln)) => cln.terminate().await,
            Some(LightningNode::Ldk) => {
                // This is not implemented because the LDK node lives in
                // the gateway process and cannot be stopped independently.
                unimplemented!("LDK node termination not implemented")
            }
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
        gatewayd_path: &PathBuf,
        gateway_cli_path: &PathBuf,
        gateway_cln_extension_path: &PathBuf,
        bitcoind: Bitcoind,
    ) -> Result<()> {
        let ln = self
            .ln
            .as_ref()
            .expect("Lightning Node should exist")
            .clone();
        let ln_type = ln.name();

        // We need to restart the CLN extension so that it has the same version as
        // gatewayd
        if ln_type == LightningNodeType::Cln {
            self.stop_lightning_node().await?;
        }
        self.process.terminate().await?;
        std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", gatewayd_path);
        std::env::set_var("FM_GATEWAY_CLI_BASE_EXECUTABLE", gateway_cli_path);
        std::env::set_var(
            "FM_GATEWAY_CLN_EXTENSION_BASE_EXECUTABLE",
            gateway_cln_extension_path,
        );

        let new_ln = match ln_type {
            LightningNodeType::Cln => {
                let new_cln = Lightningd::new(process_mgr, bitcoind).await?;
                LightningNode::Cln(new_cln)
            }
            _ => ln,
        };
        let new_gw = Self::new(process_mgr, new_ln.clone()).await?;
        self.process = new_gw.process;
        self.set_lightning_node(new_ln);
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let gateway_cln_extension_version =
            crate::util::GatewayClnExtension::version_or_default().await;
        info!(
            ?gatewayd_version,
            ?gateway_cli_version,
            ?gateway_cln_extension_version,
            "upgraded gatewayd, gateway-cli, and gateway-cln-extension"
        );
        Ok(())
    }

    pub fn cmd(&self) -> Command {
        cmd!(
            crate::util::get_gateway_cli_path(),
            "--rpcpassword=theresnosecondbest",
            "-a",
            &self.addr
        )
    }

    pub fn change_password(&self, old_password: &str, new_password: &str) -> Command {
        cmd!(
            crate::util::get_gateway_cli_path(),
            "--rpcpassword",
            old_password,
            "-a",
            &self.addr,
            "set-configuration",
            "--password",
            new_password,
        )
    }

    pub async fn get_info(&self) -> Result<serde_json::Value> {
        retry(
            "Getting gateway info via gateway-cli info",
            backoff_util::aggressive_backoff(),
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

    pub async fn lightning_pubkey(&self) -> Result<PublicKey> {
        let info = self.get_info().await?;
        let lightning_pub_key = info["lightning_pub_key"]
            .as_str()
            .context("lightning_pub_key must be a string")?
            .to_owned();
        Ok(lightning_pub_key.parse()?)
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

    pub async fn recover_fed(&self, fed: &Federation) -> Result<()> {
        let federation_id = fed.calculate_federation_id();
        let invite_code = fed.invite_code()?;
        info!("Recovering {federation_id}...");
        cmd!(self, "connect-fed", invite_code.clone(), "--recover=true")
            .run()
            .await?;
        Ok(())
    }

    pub async fn backup_to_fed(&self, fed: &Federation) -> Result<()> {
        let federation_id = fed.calculate_federation_id();
        cmd!(self, "backup", "--federation-id", federation_id)
            .run()
            .await?;
        Ok(())
    }

    pub fn lightning_node_type(&self) -> LightningNodeType {
        self.ln
            .as_ref()
            .expect("Gateway has no lightning node")
            .name()
    }

    pub async fn get_pegin_addr(&self, fed_id: &str) -> Result<String> {
        Ok(cmd!(self, "address", "--federation-id={fed_id}")
            .out_json()
            .await?
            .as_str()
            .context("address must be a string")?
            .to_owned())
    }

    pub async fn get_ln_onchain_address(&self) -> Result<String> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let address = if gateway_cli_version < *VERSION_0_5_0_ALPHA {
            cmd!(self, "lightning", "get-funding-address")
                .out_string()
                .await?
        } else {
            cmd!(self, "lightning", "get-ln-onchain-address")
                .out_string()
                .await?
        };

        Ok(address)
    }

    pub async fn get_mnemonic(&self) -> Result<MnemonicResponse> {
        let value = retry(
            "Getting gateway mnemonic",
            backoff_util::aggressive_backoff(),
            || async { cmd!(self, "seed").out_json().await },
        )
        .await
        .context("Getting gateway mnemonic")?;

        Ok(serde_json::from_value(value)?)
    }

    pub async fn leave_federation(&self, federation_id: FederationId) -> Result<()> {
        cmd!(self, "leave-fed", "--federation-id", federation_id)
            .run()
            .await?;
        Ok(())
    }

    pub async fn open_channel(
        &self,
        gw: &Gatewayd,
        channel_size_sats: u64,
        push_amount_sats: Option<u64>,
    ) -> Result<()> {
        let pubkey = gw.lightning_pubkey().await?;
        cmd!(
            self,
            "lightning",
            "open-channel",
            "--pubkey",
            pubkey,
            "--host",
            gw.lightning_node_addr,
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
                Ok(ChannelInfo {
                    remote_pubkey: remote_pubkey
                        .parse()
                        .expect("Lightning node returned invalid remote channel pubkey"),
                    channel_size_sats,
                    outbound_liquidity_sats,
                    inbound_liquidity_sats,
                    short_channel_id,
                })
            })
            .collect::<Result<Vec<ChannelInfo>>>()?;
        Ok(channels)
    }

    pub async fn wait_for_chain_sync(&self, bitcoind: &Bitcoind) -> Result<()> {
        poll("lightning node block processing", || async {
            let block_height = bitcoind.get_block_count().map_err(ControlFlow::Continue)? - 1;
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
