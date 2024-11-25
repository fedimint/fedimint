use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use esplora_client::Txid;
use fedimint_core::config::FederationId;
use fedimint_core::envs::{is_env_var_set, FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::BitcoinAmountOrAll;
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use fedimint_testing::gateway::LightningNodeType;
use ln_gateway::envs::FM_GATEWAY_LIGHTNING_MODULE_MODE_ENV;
use ln_gateway::lightning::ChannelInfo;
use ln_gateway::rpc::{GatewayBalances, MnemonicResponse, V1_API_ENDPOINT};
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

        let mut gateway_env: HashMap<String, String> = HashMap::from_iter([
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
        // TODO(support:v0.4.0): Run the gateway in LNv1 mode only before v0.5.0 because
        // that is the only module it supported.
        let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        if fedimintd_version < *VERSION_0_5_0_ALPHA
            || is_env_var_set(FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV)
        {
            gateway_env.insert(
                FM_GATEWAY_LIGHTNING_MODULE_MODE_ENV.to_owned(),
                "LNv1".to_string(),
            );
        }
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

    pub fn ln_type(&self) -> LightningNodeType {
        self.ln
            .as_ref()
            .expect("Gatewayd has no lightning node type")
            .name()
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
        poll("gateway connect-fed --recover=true", || async {
            cmd!(self, "connect-fed", invite_code.clone(), "--recover=true")
                .run()
                .await
                .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    pub async fn backup_to_fed(&self, fed: &Federation) -> Result<()> {
        let federation_id = fed.calculate_federation_id();
        cmd!(self, "ecash", "backup", "--federation-id", federation_id)
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
        info!("inside get_pegin_addr");
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let address = if gateway_cli_version < *VERSION_0_5_0_ALPHA {
            cmd!(self, "address", "--federation-id={fed_id}")
                .out_json()
                .await?
                .as_str()
                .context("address must be a string")?
                .to_owned()
        } else {
            cmd!(self, "ecash", "pegin", "--federation-id={fed_id}")
                .out_json()
                .await?
                .as_str()
                .context("address must be a string")?
                .to_owned()
        };
        Ok(address)
        // Ok(cmd!(self, "ecash", "pegin", "--federation-id={fed_id}")
        //     .out_json()
        //     .await?
        //     .as_str()
        //     .context("address must be a string")?
        //     .to_owned())
    }

    pub async fn get_ln_onchain_address(&self) -> Result<String> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let address = if gateway_cli_version < *VERSION_0_5_0_ALPHA {
            cmd!(self, "lightning", "get-funding-address")
                .out_string()
                .await?
        } else {
            cmd!(self, "onchain", "address").out_string().await?
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

    pub async fn create_invoice(&self, amount_msats: u64) -> Result<Bolt11Invoice> {
        Ok(Bolt11Invoice::from_str(
            &cmd!(self, "lightning", "create-invoice", amount_msats)
                .out_string()
                .await?,
        )?)
    }

    pub async fn pay_invoice(&self, invoice: Bolt11Invoice) -> Result<()> {
        cmd!(self, "lightning", "pay-invoice", invoice.to_string())
            .run()
            .await?;

        Ok(())
    }

    pub async fn send_ecash(&self, federation_id: String, amount_msats: u64) -> Result<String> {
        let value = cmd!(
            self,
            "ecash",
            "send",
            "--federation-id",
            federation_id,
            amount_msats
        )
        .out_json()
        .await?;
        let ecash: String = serde_json::from_value(
            value
                .get("notes")
                .expect("notes key does not exist")
                .clone(),
        )?;
        Ok(ecash)
    }

    pub async fn receive_ecash(&self, ecash: String) -> Result<()> {
        cmd!(self, "ecash", "receive", "--notes", ecash)
            .run()
            .await?;
        Ok(())
    }

    pub async fn get_balances(&self) -> Result<GatewayBalances> {
        let value = cmd!(self, "get-balances").out_json().await?;
        Ok(serde_json::from_value(value)?)
    }

    pub async fn ecash_balance(&self, federation_id: String) -> anyhow::Result<u64> {
        let federation_id = FederationId::from_str(&federation_id)?;
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        if gateway_cli_version < *VERSION_0_5_0_ALPHA {
            info!("calling get_balances from ecash_balance");
            let ecash_balance = cmd!(self, "balance", "--federation-id={federation_id}",)
                .out_json()
                .await?
                .as_u64()
                .unwrap();
            info!("past calling get_balances from ecash_balance");
            Ok(ecash_balance)
        } else {
            info!("calling get_balances from ecash_balance");
            let balances = self.get_balances().await?;
            info!("past calling get_balances from ecash_balance");
            let ecash_balance = balances
                .ecash_balances
                .into_iter()
                .find(|info| info.federation_id == federation_id)
                .ok_or(anyhow::anyhow!("Gateway is not joined to federation"))?
                .ecash_balance_msats
                .msats;
            Ok(ecash_balance)
        }
    }

    pub async fn send_onchain(
        &self,
        bitcoind: &Bitcoind,
        amount: BitcoinAmountOrAll,
        fee_rate: u64,
    ) -> Result<()> {
        let withdraw_address = bitcoind.get_new_address().await?;
        let value = cmd!(
            self,
            "onchain",
            "send",
            "--address",
            withdraw_address,
            "--amount",
            amount,
            "--fee-rate-sats-per-vbyte",
            fee_rate
        )
        .out_json()
        .await?;
        let txid: bitcoin::Txid = serde_json::from_value(value)?;
        bitcoind.mine_blocks(21).await?;
        let block_height = bitcoind.get_block_count().await? - 1;
        bitcoind.poll_get_transaction(txid).await?;
        self.wait_for_block_height(block_height).await?;
        Ok(())
    }

    pub async fn close_all_channels(&self, bitcoind: Bitcoind) -> Result<()> {
        let channels = self.list_active_channels().await?;
        for chan in channels {
            let remote_pubkey = chan.remote_pubkey;
            cmd!(
                self,
                "lightning",
                "close-channels-with-peer",
                "--pubkey",
                remote_pubkey
            )
            .run()
            .await?;
        }
        bitcoind.mine_blocks(50).await?;
        let block_height = bitcoind.get_block_count().await? - 1;
        self.wait_for_block_height(block_height).await?;

        Ok(())
    }

    /// Open a channel with the gateway's lightning node.
    /// Returns the txid of the funding transaction if the gateway is a new
    /// enough version to return it. Otherwise, returns `None`.
    ///
    /// TODO(support:v0.5): Remove the `Option<Txid>` return type and just
    /// return `Txid`.
    pub async fn open_channel(
        &self,
        gw: &Gatewayd,
        channel_size_sats: u64,
        push_amount_sats: Option<u64>,
    ) -> Result<Option<Txid>> {
        let pubkey = gw.lightning_pubkey().await?;

        let mut command = cmd!(
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
        );

        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version < *VERSION_0_5_0_ALPHA {
            command.run().await?;

            Ok(None)
        } else {
            Ok(Some(Txid::from_str(&command.out_string().await?)?))
        }
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

    pub async fn wait_for_block_height(&self, target_block_height: u64) -> Result<()> {
        poll("waiting for block height", || async {
            let info = self.get_info().await.map_err(ControlFlow::Continue)?;
            let value = info.get("block_height");
            if let Some(height) = value {
                let block_height: u32 =
                    serde_json::from_value(height.clone()).expect("Could not parse block height");
                if block_height >= target_block_height as u32 {
                    return Ok(());
                }
            }
            Err(ControlFlow::Continue(anyhow::anyhow!(
                "Not synced to block"
            )))
        })
        .await?;
        Ok(())
    }
}
