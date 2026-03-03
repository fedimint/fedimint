use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow};
use bitcoin::hashes::sha256;
use chrono::{DateTime, Utc};
use esplora_client::Txid;
use fedimint_core::config::FederationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{Amount, BitcoinAmountOrAll, BitcoinHash};
use fedimint_gateway_common::envs::FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE_ENV;
use fedimint_gateway_common::{
    ChannelInfo, CreateOfferResponse, GatewayBalances, GetInvoiceResponse,
    ListTransactionsResponse, ListUsersResponse, MnemonicResponse, PaymentDetails, PaymentStatus,
    PaymentSummaryResponse, UserResponse, V1_API_ENDPOINT,
};
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_testing_core::node_type::LightningNodeType;
use semver::Version;
use tracing::info;

use crate::cmd;
use crate::envs::{
    FM_GATEWAY_API_ADDR_ENV, FM_GATEWAY_DATA_DIR_ENV, FM_GATEWAY_IROH_LISTEN_ADDR_ENV,
    FM_GATEWAY_LISTEN_ADDR_ENV, FM_GATEWAY_METRICS_LISTEN_ADDR_ENV, FM_PORT_LDK_ENV,
};
use crate::external::{Bitcoind, LightningNode};
use crate::federation::Federation;
use crate::util::{Command, ProcessHandle, ProcessManager, poll, supports_lnv2};
use crate::vars::utf8;
use crate::version_constants::{VERSION_0_9_0_ALPHA, VERSION_0_10_0_ALPHA};

#[derive(Clone)]
pub struct Gatewayd {
    pub(crate) process: ProcessHandle,
    pub ln: LightningNode,
    pub addr: String,
    pub(crate) lightning_node_addr: String,
    pub gatewayd_version: Version,
    pub gw_name: String,
    pub log_path: PathBuf,
    pub gw_port: u16,
    pub ldk_port: u16,
    pub metrics_port: u16,
    pub gateway_id: String,
    pub iroh_gateway_id: Option<String>,
    pub iroh_port: u16,
    pub node_id: iroh_base::NodeId,
    pub gateway_index: usize,
}

// ==================== Gateway Client Builder ====================

/// A builder for creating gateway CLI commands with configurable endpoint (HTTP
/// or Iroh) and authentication (admin or user).
///
/// TODO: All `gateway-cli` functions from `Gatewayd` should be moved over to
/// this struct so that they can easily be executed by different users or over
/// iroh.
///
/// # Example
/// ```ignore
/// // HTTP as admin
/// gw.client().spend_ecash(fed_id, 500_000).await?;
///
/// // HTTP as user
/// gw.client().as_user("alice", "password").spend_ecash(fed_id, 500_000).await?;
///
/// // Iroh as admin
/// gw.client().iroh().get_mnemonic().await?;
///
/// // Iroh as user
/// gw.client().iroh().as_user("alice", "password").spend_ecash(fed_id, 500_000).await?;
/// ```
pub struct GatewayClient<'a> {
    gw: &'a Gatewayd,
    use_iroh: bool,
    username: Option<String>,
    password: Option<String>,
}

impl<'a> GatewayClient<'a> {
    /// Create a new gateway client for the given gateway (defaults to HTTP,
    /// admin auth)
    pub fn new(gw: &'a Gatewayd) -> Self {
        Self {
            gw,
            use_iroh: false,
            username: None,
            password: None,
        }
    }

    /// Use the Iroh endpoint instead of HTTP
    pub fn iroh(mut self) -> Self {
        self.use_iroh = true;
        self
    }

    /// Authenticate as a specific user instead of admin
    pub fn as_user(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Build the base command with the configured endpoint and authentication
    fn cmd(&self) -> Command {
        match (&self.username, &self.password, self.use_iroh) {
            // User auth over HTTP
            (Some(u), Some(p), false) => cmd!(
                crate::util::get_gateway_cli_path(),
                "--rpcuser",
                u,
                "--rpcpassword",
                p,
                "-a",
                &self.gw.addr
            ),
            // User auth over Iroh
            (Some(u), Some(p), true) => cmd!(
                crate::util::get_gateway_cli_path(),
                "--rpcuser",
                u,
                "--rpcpassword",
                p,
                "--address",
                format!("iroh://{}", self.gw.node_id),
            ),
            // Admin auth over HTTP
            (None, None, false) => cmd!(
                crate::util::get_gateway_cli_path(),
                "--rpcpassword=theresnosecondbest",
                "-a",
                &self.gw.addr
            ),
            // Admin auth over Iroh
            (None, None, true) => cmd!(
                crate::util::get_gateway_cli_path(),
                "--rpcpassword=theresnosecondbest",
                "--address",
                format!("iroh://{}", self.gw.node_id),
            ),
            // Invalid state - shouldn't happen
            _ => panic!(
                "Invalid GatewayClient state: username and password must both be set or both be None"
            ),
        }
    }

    // ==================== User Management Operations (admin only)
    // ====================

    /// Create a new user (admin only)
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        send_limit_msats: Option<u64>,
        federation_management: bool,
        fee_management: bool,
    ) -> Result<serde_json::Value> {
        let mut command = self
            .cmd()
            .arg(&"user")
            .arg(&"create")
            .arg(&"--password")
            .arg(&password)
            .arg(&username);

        if let Some(limit) = send_limit_msats {
            command = command.arg(&"--send-limit-msats").arg(&limit);
        }

        if federation_management {
            command = command.arg(&"--federation-management");
        }

        if fee_management {
            command = command.arg(&"--fee-management");
        }

        command.out_json().await
    }

    /// Delete a user
    pub async fn delete_user(&self, username: &str) -> Result<()> {
        self.cmd()
            .arg(&"user")
            .arg(&"delete")
            .arg(&username)
            .run()
            .await
    }

    /// List all users
    pub async fn list_users(&self) -> Result<ListUsersResponse> {
        let response = self.cmd().arg(&"user").arg(&"list").out_json().await?;
        serde_json::from_value(response).context("Failed to parse list users response")
    }

    /// Get a specific user
    pub async fn get_user(&self, username: &str) -> Result<Option<UserResponse>> {
        let response = self
            .cmd()
            .arg(&"user")
            .arg(&"get")
            .arg(&username)
            .out_json()
            .await?;
        if response.is_null() {
            Ok(None)
        } else {
            Ok(Some(
                serde_json::from_value(response).context("Failed to parse user response")?,
            ))
        }
    }

    // ==================== Spend Operations ====================

    /// Spend ecash (for testing spend limits)
    pub async fn spend_ecash(
        &self,
        federation_id: FederationId,
        amount_msats: u64,
    ) -> Result<serde_json::Value> {
        self.cmd()
            .arg(&"ecash")
            .arg(&"send")
            .arg(&"--federation-id")
            .arg(&federation_id)
            .arg(&amount_msats)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }

    /// Withdraw ecash (for testing spend limits)
    pub async fn withdraw(
        &self,
        federation_id: FederationId,
        amount: BitcoinAmountOrAll,
        address: &str,
    ) -> Result<serde_json::Value> {
        let amount_str = match amount {
            BitcoinAmountOrAll::Amount(btc) => btc.to_sat().to_string(),
            BitcoinAmountOrAll::All => "all".to_string(),
        };
        self.cmd()
            .arg(&"ecash")
            .arg(&"pegout")
            .arg(&"--federation-id")
            .arg(&federation_id)
            .arg(&"--amount")
            .arg(&amount_str)
            .arg(&"--address")
            .arg(&address)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }

    /// Pay invoice (for testing spend limits)
    pub async fn pay_invoice(&self, invoice: Bolt11Invoice) -> Result<serde_json::Value> {
        self.cmd()
            .arg(&"lightning")
            .arg(&"pay-invoice")
            .arg(&invoice)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }

    /// Send onchain (for testing spend limits)
    pub async fn send_onchain(
        &self,
        amount: BitcoinAmountOrAll,
        address: &str,
        fee_rate: u64,
    ) -> Result<Txid> {
        let amount_str = match amount {
            BitcoinAmountOrAll::Amount(btc) => btc.to_sat().to_string(),
            BitcoinAmountOrAll::All => "all".to_string(),
        };
        let value = self
            .cmd()
            .arg(&"onchain")
            .arg(&"send")
            .arg(&"--amount")
            .arg(&amount_str)
            .arg(&"--address")
            .arg(&address)
            .arg(&"--fee-rate-sats-per-vbyte")
            .arg(&fee_rate)
            .out_json()
            .await?;
        let txid: Txid =
            serde_json::from_value(value).context("Could not parse onchain send response")?;
        Ok(txid)
    }

    /// Open channel
    pub async fn open_channel(
        &self,
        pubkey: &str,
        host: &str,
        channel_size_sats: u64,
        push_amount_sats: u64,
    ) -> Result<Txid> {
        let output = self
            .cmd()
            .arg(&"lightning")
            .arg(&"open-channel")
            .arg(&"--pubkey")
            .arg(&pubkey)
            .arg(&"--host")
            .arg(&host)
            .arg(&"--channel-size-sats")
            .arg(&channel_size_sats)
            .arg(&"--push-amount-sats")
            .arg(&push_amount_sats)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_string()
            .await?;
        Ok(Txid::from_str(&output)?)
    }

    /// Pay BOLT12 offer (for testing spend limits)
    pub async fn pay_offer(&self, offer: &str, amount: Option<Amount>) -> Result<()> {
        let mut command = self
            .cmd()
            .arg(&"lightning")
            .arg(&"pay-offer")
            .arg(&"--offer")
            .arg(&offer);

        if let Some(amount) = amount {
            command = command.arg(&"--amount-msat").arg(&amount.msats);
        }

        command.run().await
    }

    // ==================== Federation Management Operations ====================

    /// Connect to a federation (for testing federation management permission)
    pub async fn connect_federation(&self, invite_code: &str) -> Result<serde_json::Value> {
        self.cmd()
            .arg(&"connect-fed")
            .arg(&"--invite-code")
            .arg(&invite_code)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }

    /// Leave a federation (for testing federation management permission)
    pub async fn leave_federation(&self, federation_id: FederationId) -> Result<serde_json::Value> {
        self.cmd()
            .arg(&"leave-fed")
            .arg(&"--federation-id")
            .arg(&federation_id)
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }

    // ==================== Fee Management Operations ====================

    /// Set fees (for testing fee management permission)
    pub async fn set_fees(
        &self,
        federation_id: FederationId,
        ln_ppm: u64,
        ln_base_msat: u64,
    ) -> Result<()> {
        self.cmd()
            .arg(&"cfg")
            .arg(&"set-fees")
            .arg(&"--federation-id")
            .arg(&federation_id)
            .arg(&"--ln-ppm")
            .arg(&ln_ppm)
            .arg(&"--ln-base")
            .arg(&format!("{ln_base_msat} msat"))
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .run()
            .await
    }

    // ==================== Admin-Only Operations ====================

    /// Get gateway mnemonic (admin only)
    pub async fn get_mnemonic(&self) -> Result<serde_json::Value> {
        self.cmd()
            .arg(&"seed")
            .kill_on_drop(true)
            .env("RUST_BACKTRACE", "1")
            .env("RUST_LIB_BACKTRACE", "0")
            .out_json()
            .await
    }
}

impl Gatewayd {
    pub async fn new(
        process_mgr: &ProcessManager,
        ln: LightningNode,
        gateway_index: usize,
    ) -> Result<Self> {
        let ln_type = ln.ln_type();
        let (gw_name, port, lightning_node_port, metrics_port) = match &ln {
            LightningNode::Lnd(_) => (
                "gatewayd-lnd".to_string(),
                process_mgr.globals.FM_PORT_GW_LND,
                process_mgr.globals.FM_PORT_LND_LISTEN,
                process_mgr.globals.FM_PORT_GW_LND_METRICS,
            ),
            LightningNode::Ldk {
                name,
                gw_port,
                ldk_port,
                metrics_port,
            } => (
                name.to_owned(),
                gw_port.to_owned(),
                ldk_port.to_owned(),
                metrics_port.to_owned(),
            ),
        };
        let test_dir = &process_mgr.globals.FM_TEST_DIR;
        let addr = format!("http://127.0.0.1:{port}/{V1_API_ENDPOINT}");
        let lightning_node_addr = format!("127.0.0.1:{lightning_node_port}");
        let iroh_endpoint = process_mgr
            .globals
            .gatewayd_overrides
            .gateway_iroh_endpoints
            .get(gateway_index)
            .expect("No gateway for index");

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
            (FM_PORT_LDK_ENV.to_owned(), lightning_node_port.to_string()),
            (
                FM_GATEWAY_IROH_LISTEN_ADDR_ENV.to_owned(),
                format!("127.0.0.1:{}", iroh_endpoint.port()),
            ),
            (
                FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE_ENV.to_owned(),
                iroh_endpoint.secret_key(),
            ),
            (
                FM_GATEWAY_METRICS_LISTEN_ADDR_ENV.to_owned(),
                format!("127.0.0.1:{metrics_port}"),
            ),
        ]);

        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version < *VERSION_0_9_0_ALPHA {
            let mode = if supports_lnv2() {
                "All"
            } else {
                info!(target: LOG_DEVIMINT, "LNv2 is not supported, running gatewayd in LNv1 mode");
                "LNv1"
            };
            gateway_env.insert(
                "FM_GATEWAY_LIGHTNING_MODULE_MODE".to_owned(),
                mode.to_string(),
            );
        }

        if ln_type == LightningNodeType::Ldk {
            gateway_env.insert("FM_LDK_ALIAS".to_owned(), gw_name.clone());

            // Prior to `v0.9.0`, only LDK could connect to bitcoind
            if gatewayd_version < *VERSION_0_9_0_ALPHA {
                let btc_rpc_port = process_mgr.globals.FM_PORT_BTC_RPC;
                gateway_env.insert(
                    "FM_LDK_BITCOIND_RPC_URL".to_owned(),
                    format!("http://bitcoin:bitcoin@127.0.0.1:{btc_rpc_port}"),
                );
            }
        }

        let process = process_mgr
            .spawn_daemon(
                &gw_name,
                cmd!(crate::util::Gatewayd, ln_type).envs(gateway_env),
            )
            .await?;

        let (gateway_id, iroh_gateway_id) = poll(
            "waiting for gateway to be ready to respond to rpc",
            || async {
                // Once the gateway id is available via RPC, the gateway is ready
                let info = cmd!(
                    crate::util::get_gateway_cli_path(),
                    "--rpcpassword",
                    "theresnosecondbest",
                    "-a",
                    addr,
                    "info"
                )
                .out_json()
                .await
                .map_err(ControlFlow::Continue)?;
                let (gateway_id, iroh_gateway_id) = if gatewayd_version < *VERSION_0_10_0_ALPHA {
                    let gateway_id = info["gateway_id"]
                        .as_str()
                        .context("gateway_id must be a string")
                        .map_err(ControlFlow::Break)?
                        .to_owned();
                    (gateway_id, None)
                } else {
                    let gateway_id = info["registrations"]["http"][1]
                        .as_str()
                        .context("gateway id must be a string")
                        .map_err(ControlFlow::Break)?
                        .to_owned();
                    let iroh_gateway_id = info["registrations"]["iroh"][1]
                        .as_str()
                        .context("gateway id must be a string")
                        .map_err(ControlFlow::Break)?
                        .to_owned();
                    (gateway_id, Some(iroh_gateway_id))
                };

                Ok((gateway_id, iroh_gateway_id))
            },
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
            gw_port: port,
            ldk_port: lightning_node_port,
            metrics_port,
            gateway_id,
            iroh_gateway_id,
            iroh_port: iroh_endpoint.port(),
            node_id: iroh_endpoint.node_id(),
            gateway_index,
        };

        Ok(gatewayd)
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = ln_node;
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        info!(target: LOG_DEVIMINT, "Stopping lightning node");
        match self.ln.clone() {
            LightningNode::Lnd(lnd) => lnd.terminate().await,
            LightningNode::Ldk {
                name: _,
                gw_port: _,
                ldk_port: _,
                metrics_port: _,
            } => {
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

        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version < *VERSION_0_9_0_ALPHA && supports_lnv2() {
            info!(target: LOG_DEVIMINT, "LNv2 is now supported, running in All mode");
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe { std::env::set_var("FM_GATEWAY_LIGHTNING_MODULE_MODE", "All") };
        }

        let new_ln = ln;
        let new_gw = Self::new(process_mgr, new_ln.clone(), self.gateway_index).await?;
        self.process = new_gw.process;
        self.set_lightning_node(new_ln);
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        info!(
            target: LOG_DEVIMINT,
            ?gatewayd_version,
            ?gateway_cli_version,
            "upgraded gatewayd and gateway-cli"
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

    pub async fn gateway_id(&self) -> Result<String> {
        let info = self.get_info().await?;
        let gateway_id = info["gateway_id"]
            .as_str()
            .context("gateway_id must be a string")?
            .to_owned();
        Ok(gateway_id)
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

    pub async fn get_info_iroh(&self) -> Result<serde_json::Value> {
        cmd!(
            crate::util::get_gateway_cli_path(),
            "--rpcpassword=theresnosecondbest",
            "--address",
            format!("iroh://{}", self.node_id),
            "info",
        )
        .out_json()
        .await
    }

    pub async fn lightning_pubkey(&self) -> Result<PublicKey> {
        let info = self.get_info().await?;
        let lightning_pub_key = if self.gatewayd_version < *VERSION_0_10_0_ALPHA {
            info["lightning_pub_key"]
                .as_str()
                .context("lightning_pub_key must be a string")?
                .to_owned()
        } else {
            info["lightning_info"]["connected"]["public_key"]
                .as_str()
                .context("lightning_pub_key must be a string")?
                .to_owned()
        };

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
        info!(target: LOG_DEVIMINT, federation_id = %federation_id, "Recovering...");
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
        Ok(cmd!(self, "ecash", "pegin", "--federation-id={fed_id}")
            .out_json()
            .await?
            .as_str()
            .context("address must be a string")?
            .to_owned())
    }

    pub async fn get_ln_onchain_address(&self) -> Result<String> {
        cmd!(self, "onchain", "address").out_string().await
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
        self.client().pay_invoice(invoice).await?;
        Ok(())
    }

    pub async fn send_ecash(&self, federation_id: String, amount_msats: u64) -> Result<String> {
        let fed_id = FederationId::from_str(&federation_id)?;
        let value = self.client().spend_ecash(fed_id, amount_msats).await?;
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

    pub async fn send_onchain(
        &self,
        bitcoind: &Bitcoind,
        amount: BitcoinAmountOrAll,
        fee_rate: u64,
    ) -> Result<bitcoin::Txid> {
        let withdraw_address = bitcoind.get_new_address().await?;
        self.client()
            .send_onchain(amount, &withdraw_address.to_string(), fee_rate)
            .await
    }

    pub async fn close_channel(&self, remote_pubkey: PublicKey, force: bool) -> Result<()> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let mut close_channel = if force && gateway_cli_version >= *VERSION_0_9_0_ALPHA {
            cmd!(
                self,
                "lightning",
                "close-channels-with-peer",
                "--pubkey",
                remote_pubkey,
                "--force",
            )
        } else if gateway_cli_version < *VERSION_0_10_0_ALPHA {
            cmd!(
                self,
                "lightning",
                "close-channels-with-peer",
                "--pubkey",
                remote_pubkey,
            )
        } else {
            cmd!(
                self,
                "lightning",
                "close-channels-with-peer",
                "--pubkey",
                remote_pubkey,
                "--sats-per-vbyte",
                "10",
            )
        };

        close_channel.run().await?;

        Ok(())
    }

    pub async fn close_all_channels(&self, force: bool) -> Result<()> {
        let channels = self.list_channels().await?;

        for chan in channels {
            let remote_pubkey = chan.remote_pubkey;
            self.close_channel(remote_pubkey, force).await?;
        }

        Ok(())
    }

    /// Open a channel with the gateway's lightning node, returning the funding
    /// transaction txid.
    pub async fn open_channel(
        &self,
        gw: &Gatewayd,
        channel_size_sats: u64,
        push_amount_sats: Option<u64>,
    ) -> Result<Txid> {
        let pubkey = gw.lightning_pubkey().await?;
        self.client()
            .open_channel(
                &pubkey.to_string(),
                &gw.lightning_node_addr,
                channel_size_sats,
                push_amount_sats.unwrap_or(0),
            )
            .await
    }

    pub async fn list_channels(&self) -> Result<Vec<ChannelInfo>> {
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let channels = if gateway_cli_version >= *VERSION_0_9_0_ALPHA {
            cmd!(self, "lightning", "list-channels").out_json().await?
        } else {
            cmd!(self, "lightning", "list-active-channels")
                .out_json()
                .await?
        };

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
                let is_active = channel["is_active"].as_bool().unwrap_or(true);
                let funding_outpoint = channel.get("funding_outpoint").map(|v| {
                    serde_json::from_value::<bitcoin::OutPoint>(v.clone())
                        .expect("Could not deserialize outpoint")
                });
                let remote_node_alias = channel
                    .get("remote_node_alias")
                    .map(std::string::ToString::to_string);
                Ok(ChannelInfo {
                    remote_pubkey: remote_pubkey
                        .parse()
                        .expect("Lightning node returned invalid remote channel pubkey"),
                    channel_size_sats,
                    outbound_liquidity_sats,
                    inbound_liquidity_sats,
                    is_active,
                    funding_outpoint,
                    remote_node_alias,
                })
            })
            .collect::<Result<Vec<ChannelInfo>>>()?;
        Ok(channels)
    }

    pub async fn wait_for_block_height(&self, target_block_height: u64) -> Result<()> {
        poll("waiting for block height", || async {
            let info = self.get_info().await.map_err(ControlFlow::Continue)?;

            let height_value = if self.gatewayd_version < *VERSION_0_10_0_ALPHA {
                info["block_height"].clone()
            } else {
                info["lightning_info"]["connected"]["block_height"].clone()
            };

            let block_height: Option<u32> = serde_json::from_value(height_value)
                .context("Could not parse block height")
                .map_err(ControlFlow::Continue)?;
            let Some(block_height) = block_height else {
                return Err(ControlFlow::Continue(anyhow!("Not synced any blocks yet")));
            };

            let synced_value = if self.gatewayd_version < *VERSION_0_10_0_ALPHA {
                info["synced_to_chain"].clone()
            } else {
                info["lightning_info"]["connected"]["synced_to_chain"].clone()
            };
            let synced = synced_value
                .as_bool()
                .expect("Could not get synced_to_chain");
            if block_height >= target_block_height as u32 && synced {
                return Ok(());
            }

            Err(ControlFlow::Continue(anyhow!("Not synced to block")))
        })
        .await?;
        Ok(())
    }

    pub async fn get_lightning_fee(&self, fed_id: String) -> Result<PaymentFee> {
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

        let lightning_fee = fed["config"]["lightning_fee"].clone();
        let base: Amount = serde_json::from_value(lightning_fee["base"].clone())
            .map_err(|e| anyhow!("Couldnt parse base: {}", e))?;
        let parts_per_million: u64 =
            serde_json::from_value(lightning_fee["parts_per_million"].clone())
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

        Ok(())
    }

    pub async fn set_federation_transaction_fee(
        &self,
        fed_id: String,
        base: u64,
        ppm: u64,
    ) -> Result<()> {
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

        Ok(())
    }

    pub async fn payment_summary(&self) -> Result<PaymentSummaryResponse> {
        let out_json = cmd!(self, "payment-summary").out_json().await?;
        Ok(serde_json::from_value(out_json).expect("Could not deserialize PaymentSummaryResponse"))
    }

    pub async fn wait_bolt11_invoice(&self, payment_hash: Vec<u8>) -> Result<()> {
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

    pub async fn list_transactions(
        &self,
        start: SystemTime,
        end: SystemTime,
    ) -> Result<Vec<PaymentDetails>> {
        let start_datetime: DateTime<Utc> = start.into();
        let end_datetime: DateTime<Utc> = end.into();
        let response = cmd!(
            self,
            "lightning",
            "list-transactions",
            "--start-time",
            start_datetime.to_rfc3339(),
            "--end-time",
            end_datetime.to_rfc3339()
        )
        .out_json()
        .await?;
        let transactions = serde_json::from_value::<ListTransactionsResponse>(response)?;
        Ok(transactions.transactions)
    }

    pub async fn create_offer(&self, amount: Option<Amount>) -> Result<String> {
        let offer_value = if let Some(amount) = amount {
            cmd!(
                self,
                "lightning",
                "create-offer",
                "--amount-msat",
                amount.msats
            )
            .out_json()
            .await?
        } else {
            cmd!(self, "lightning", "create-offer").out_json().await?
        };
        let offer_response = serde_json::from_value::<CreateOfferResponse>(offer_value)
            .expect("Could not parse offer response");
        Ok(offer_response.offer)
    }

    pub async fn pay_offer(&self, offer: String, amount: Option<Amount>) -> Result<()> {
        self.client().pay_offer(&offer, amount).await
    }

    // ==================== User Management Methods ====================

    /// Create a `GatewayClient` builder for making authenticated requests.
    /// Defaults to HTTP endpoint with admin authentication.
    ///
    /// # Example
    /// ```ignore
    /// // HTTP as admin
    /// gw.client().spend_ecash(fed_id, 500_000).await?;
    ///
    /// // HTTP as user
    /// gw.client().as_user("alice", "password").spend_ecash(fed_id, 500_000).await?;
    ///
    /// // Iroh as admin
    /// gw.client().iroh().get_mnemonic().await?;
    ///
    /// // Iroh as user
    /// gw.client().iroh().as_user("alice", "password").set_fees(fed_id, 100,
    /// 1000).await?;
    /// ```
    pub fn client(&self) -> GatewayClient<'_> {
        GatewayClient::new(self)
    }
}
