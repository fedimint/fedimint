use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use bitcoin::hashes::sha256;
use esplora_client::Txid;
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{Amount, BitcoinAmountOrAll, BitcoinHash};
use fedimint_gateway_common::{
    ChannelInfo, GatewayBalances, GetInvoiceResponse, MnemonicResponse, PaymentStatus,
    PaymentSummaryResponse, V1_API_ENDPOINT,
};
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_testing::ln::LightningNodeType;
use semver::Version;
use tracing::info;

use crate::cmd;
use crate::envs::{FM_GATEWAY_API_ADDR_ENV, FM_GATEWAY_DATA_DIR_ENV, FM_GATEWAY_LISTEN_ADDR_ENV};
use crate::external::{Bitcoind, LightningNode};
use crate::federation::Federation;
use crate::util::{Command, ProcessHandle, ProcessManager, poll, supports_lnv2};
use crate::vars::utf8;
use crate::version_constants::{VERSION_0_5_0_ALPHA, VERSION_0_6_0_ALPHA, VERSION_0_7_0_ALPHA};

#[derive(Clone)]
pub struct Gatewayd {
    pub(crate) process: ProcessHandle,
    pub ln: LightningNode,
    pub addr: String,
    pub(crate) lightning_node_addr: String,
    pub gatewayd_version: Version,
    pub gw_name: String,
    pub log_path: PathBuf,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: LightningNode) -> Result<Self> {
        let ln_type = ln.ln_type();
        let gw_name = match &ln {
            LightningNode::Lnd(_) => "gatewayd-lnd".to_string(),
            LightningNode::Ldk { name } => name.to_owned(),
        };
        let test_dir = &process_mgr.globals.FM_TEST_DIR;

        let port = match ln {
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_GW_LND,
            LightningNode::Ldk { name: _ } => process_mgr.globals.FM_PORT_GW_LDK,
        };
        let addr = format!("http://127.0.0.1:{port}/{V1_API_ENDPOINT}");

        let lightning_node_port = match ln {
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_LND_LISTEN,
            LightningNode::Ldk { name: _ } => process_mgr.globals.FM_PORT_LDK,
        };
        let lightning_node_addr = format!("127.0.0.1:{lightning_node_port}");

        let mut gateway_env: HashMap<String, String> = HashMap::from_iter([
            (
                FM_GATEWAY_DATA_DIR_ENV.to_owned(),
                format!("{}/{gw_name}", utf8(test_dir)),
            ),
            (
                FM_GATEWAY_LISTEN_ADDR_ENV.to_owned(),
                format!("127.0.0.1:{port}"),
            ),
            (FM_GATEWAY_API_ADDR_ENV.to_owned(), addr.clone()),
        ]);
        if !supports_lnv2() {
            tracing::info!("LNv2 is not supported, running gatewayd in LNv1 mode");
            gateway_env.insert(
                "FM_GATEWAY_LIGHTNING_MODULE_MODE".to_owned(),
                "LNv1".to_string(),
            );
        }
        if ln_type == LightningNodeType::Ldk {
            gateway_env.insert("FM_LDK_ALIAS".to_owned(), gw_name.clone());
        }
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        let process = process_mgr
            .spawn_daemon(
                &gw_name,
                Gatewayd::start_gatewayd(&ln_type, &gatewayd_version).envs(gateway_env),
            )
            .await?;

        let log_path = process_mgr
            .globals
            .FM_LOGS_DIR
            .join(format!("{gw_name}.log"));
        let gatewayd = Self {
            process,
            ln,
            addr,
            lightning_node_addr,
            gatewayd_version,
            gw_name,
            log_path,
        };
        poll(
            "waiting for gateway to be ready to respond to rpc",
            || async { gatewayd.gateway_id().await.map_err(ControlFlow::Continue) },
        )
        .await?;
        Ok(gatewayd)
    }

    fn is_forced_current(&self) -> bool {
        self.ln.ln_type() == LightningNodeType::Ldk && self.gatewayd_version < *VERSION_0_6_0_ALPHA
    }

    fn start_gatewayd(ln_type: &LightningNodeType, gatewayd_version: &Version) -> Command {
        // If an LDK gateway is trying to spawn prior to v0.6, just use most recent
        // version
        if *ln_type == LightningNodeType::Ldk && *gatewayd_version < *VERSION_0_6_0_ALPHA {
            cmd!("gatewayd", ln_type)
        } else {
            cmd!(crate::util::Gatewayd, ln_type)
        }
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = ln_node;
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        info!("Stopping lightning node");
        match self.ln.clone() {
            LightningNode::Lnd(lnd) => lnd.terminate().await,
            LightningNode::Ldk { name: _ } => {
                // This is not implemented because the LDK node lives in
                // the gateway process and cannot be stopped independently.
                unimplemented!("LDK node termination not implemented")
            }
        }
    }

    /// Restarts the gateway using the provided `bin_path`, which is useful for
    /// testing upgrades.
    pub async fn restart_with_bin(
        &mut self,
        process_mgr: &ProcessManager,
        gatewayd_path: &PathBuf,
        gateway_cli_path: &PathBuf,
    ) -> Result<()> {
        let ln = self.ln.clone();

        self.process.terminate().await?;
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", gatewayd_path) };
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("FM_GATEWAY_CLI_BASE_EXECUTABLE", gateway_cli_path) };

        if supports_lnv2() {
            tracing::info!("LNv2 is now supported, running in All mode");
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe { std::env::set_var("FM_GATEWAY_LIGHTNING_MODULE_MODE", "All") };
        }

        let new_ln = ln;
        let new_gw = Self::new(process_mgr, new_ln.clone()).await?;
        self.process = new_gw.process;
        self.set_lightning_node(new_ln);
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        info!(
            ?gatewayd_version,
            ?gateway_cli_version,
            "upgraded gatewayd and gateway-cli"
        );
        Ok(())
    }

    pub fn cmd(&self) -> Command {
        if self.is_forced_current() {
            cmd!(
                "gateway-cli",
                "--rpcpassword=theresnosecondbest",
                "-a",
                &self.addr
            )
        } else {
            cmd!(
                crate::util::get_gateway_cli_path(),
                "--rpcpassword=theresnosecondbest",
                "-a",
                &self.addr
            )
        }
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

    pub async fn get_pegin_addr(&self, fed_id: &str) -> Result<String> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;

        // TODO(support:v0.4): `ecash pegin` was introduced in v0.5.0
        // see: https://github.com/fedimint/fedimint/pull/6270
        let address = if !self.is_forced_current() && gateway_cli_version < *VERSION_0_5_0_ALPHA {
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
    }

    pub async fn get_ln_onchain_address(&self) -> Result<String> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let address = if !self.is_forced_current() && gateway_cli_version < *VERSION_0_5_0_ALPHA {
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
        // TODO(support:v0.4): `get_balances` was introduced in v0.5.0
        // see: https://github.com/fedimint/fedimint/pull/5823
        if !self.is_forced_current() && gateway_cli_version < *VERSION_0_5_0_ALPHA {
            let ecash_balance = cmd!(self, "balance", "--federation-id={federation_id}",)
                .out_json()
                .await?
                .as_u64()
                .unwrap();
            Ok(ecash_balance)
        } else {
            let balances = self.get_balances().await?;
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
                let block_height: Option<u32> = serde_json::from_value(height.clone())
                    .context("Could not parse block height")
                    .map_err(ControlFlow::Continue)?;
                let Some(block_height) = block_height else {
                    return Err(ControlFlow::Continue(anyhow!("Not synced any blocks yet")));
                };
                if block_height >= target_block_height as u32 {
                    return Ok(());
                }
            }
            Err(ControlFlow::Continue(anyhow!("Not synced to block")))
        })
        .await?;
        Ok(())
    }

    pub async fn get_lightning_fee(&self, fed_id: String) -> Result<PaymentFee> {
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        let (fee_key, base_key, ppm_key) =
            if gatewayd_version >= *VERSION_0_6_0_ALPHA || self.is_forced_current() {
                ("lightning_fee", "base", "parts_per_million")
            } else {
                ("routing_fees", "base_msat", "proportional_millionths")
            };

        let info_value = self.get_info().await?;
        let federations = info_value["federations"]
            .as_array()
            .expect("federations is an array");

        let fed = federations
            .iter()
            .find(|fed| {
                serde_json::from_value::<String>(fed["federation_id"].clone())
                    .expect("could not deserialize federation_id")
                    == fed_id
            })
            .ok_or_else(|| anyhow!("Federation not found"))?;

        let lightning_fee = if gatewayd_version >= *VERSION_0_6_0_ALPHA || self.is_forced_current()
        {
            fed["config"][fee_key].clone()
        } else {
            fed[fee_key].clone()
        };

        let base: Amount = serde_json::from_value(lightning_fee[base_key].clone())
            .map_err(|e| anyhow!("Couldnt parse base: {}", e))?;
        let parts_per_million: u64 = serde_json::from_value(lightning_fee[ppm_key].clone())
            .map_err(|e| anyhow!("Couldnt parse parts_per_million: {}", e))?;

        Ok(PaymentFee {
            base,
            parts_per_million,
        })
    }

    pub async fn set_federation_routing_fee(
        &self,
        fed_id: String,
        base: u64,
        ppm: u64,
    ) -> Result<()> {
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if !self.is_forced_current() && gatewayd_version < *VERSION_0_6_0_ALPHA {
            let new_fed_routing_fees = format!("{fed_id},{base},{ppm}");
            cmd!(
                self,
                "set-configuration",
                "--per-federation-routing-fees",
                new_fed_routing_fees
            )
            .run()
            .await?;
        } else {
            cmd!(
                self,
                "cfg",
                "set-fees",
                "--federation-id",
                fed_id,
                "--ln-base",
                base,
                "--ln-ppm",
                ppm
            )
            .run()
            .await?;
        }

        Ok(())
    }

    pub async fn set_federation_transaction_fee(
        &self,
        fed_id: String,
        base: u64,
        ppm: u64,
    ) -> Result<()> {
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version >= *VERSION_0_6_0_ALPHA || self.is_forced_current() {
            cmd!(
                self,
                "cfg",
                "set-fees",
                "--federation-id",
                fed_id,
                "--tx-base",
                base,
                "--tx-ppm",
                ppm
            )
            .run()
            .await?;
        }

        Ok(())
    }

    pub async fn payment_summary(&self) -> Result<PaymentSummaryResponse> {
        let out_json = cmd!(self, "payment-summary").out_json().await?;
        Ok(serde_json::from_value(out_json).expect("Could not deserialize PaymentSummaryResponse"))
    }

    pub async fn wait_bolt11_invoice(&self, payment_hash: Vec<u8>) -> Result<()> {
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version < *VERSION_0_7_0_ALPHA {
            if let LightningNode::Lnd(lnd) = &self.ln {
                return lnd.wait_bolt11_invoice(payment_hash).await;
            }
        }

        let payment_hash =
            sha256::Hash::from_slice(&payment_hash).expect("Could not parse payment hash");
        let invoice_val = cmd!(
            self,
            "lightning",
            "get-invoice",
            "--payment-hash",
            payment_hash
        )
        .out_json()
        .await?;
        let invoice: GetInvoiceResponse =
            serde_json::from_value(invoice_val).expect("Could not parse GetInvoiceResponse");
        anyhow::ensure!(invoice.status == PaymentStatus::Succeeded);

        Ok(())
    }
}
