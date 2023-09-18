use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoincore_rpc::RpcApi;
use federation::Federation;
use fedimint_client::module::init::{ClientModuleInitRegistry, DynClientModuleInit};
use fedimint_client_legacy::modules::mint::MintClientGen;
use fedimint_client_legacy::{module_decode_stubs, UserClient, UserClientConfig};
use fedimint_core::admin_client::WsAdminClient;
use fedimint_core::config::load_from_file;
use fedimint_core::db::Database;
use fedimint_ln_client::LightningClientGen;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_wallet_client::WalletClientGen;
use tracing::{debug, info};

pub mod util;
pub mod vars;
use util::*;
use vars::utf8;

mod external;
pub use external::{
    external_daemons, open_channel, Bitcoind, Electrs, Esplora, ExternalDaemons, LightningNode,
    Lightningd, Lnd,
};

pub mod federation;

pub struct DevFed {
    pub bitcoind: Bitcoind,
    pub cln: Lightningd,
    pub lnd: Lnd,
    pub fed: Federation,
    pub gw_cln: Gatewayd,
    pub gw_lnd: Gatewayd,
    pub electrs: Electrs,
    pub esplora: Esplora,
}

#[derive(Clone)]
pub struct Gatewayd {
    _process: ProcessHandle,
    pub ln: Option<LightningNode>,
    addr: String,
}

impl Gatewayd {
    pub async fn new(process_mgr: &ProcessManager, ln: LightningNode) -> Result<Self> {
        let ln_name = ln.name();
        let test_dir = &process_mgr.globals.FM_TEST_DIR;
        let port = match ln {
            LightningNode::Cln(_) => process_mgr.globals.FM_PORT_GW_CLN,
            LightningNode::Lnd(_) => process_mgr.globals.FM_PORT_GW_LND,
        };
        let addr = format!("http://127.0.0.1:{port}");
        let gateway_env: HashMap<String, String> = HashMap::from_iter([
            (
                "FM_GATEWAY_DATA_DIR".to_owned(),
                format!("{}/{ln_name}", utf8(test_dir)),
            ),
            (
                "FM_GATEWAY_LISTEN_ADDR".to_owned(),
                format!("127.0.0.1:{port}"),
            ),
            ("FM_GATEWAY_API_ADDR".to_owned(), addr.clone()),
        ]);
        let process = process_mgr
            .spawn_daemon(
                &format!("gatewayd-{ln_name}"),
                cmd!("gatewayd", ln_name).envs(gateway_env),
            )
            .await?;

        Ok(Self {
            ln: Some(ln),
            _process: process,
            addr,
        })
    }

    pub fn set_lightning_node(&mut self, ln_node: LightningNode) {
        self.ln = Some(ln_node);
    }

    pub async fn stop_lightning_node(&mut self) -> Result<()> {
        tracing::info!("Stopping lightning node");
        match self.ln.take() {
            Some(LightningNode::Lnd(lnd)) => lnd.terminate().await,
            Some(LightningNode::Cln(cln)) => cln.terminate().await,
            None => Err(anyhow::anyhow!(
                "Cannot stop an already stopped Lightning Node"
            )),
        }
    }

    pub async fn cmd(&self) -> Command {
        cmd!(
            "gateway-cli",
            "--rpcpassword=theresnosecondbest",
            "-a",
            &self.addr
        )
    }

    pub async fn gateway_id(&self) -> Result<String> {
        let info = cmd!(self, "info").out_json().await?;
        let gateway_id = info["gateway_id"]
            .as_str()
            .context("gateway_id must be a string")?
            .to_owned();
        Ok(gateway_id)
    }

    pub async fn connect_fed(&self, fed: &Federation) -> Result<()> {
        let invite_code = fed.invite_code()?;
        poll_max_retries("gateway connect-fed", 60, || async {
            match cmd!(self, "connect-fed", invite_code.clone()).run().await {
                Ok(_) => Ok(true),
                Err(e) => {
                    debug!("gateway-cli connect-fed failed {:?}", e);
                    Ok(false)
                }
            }
        })
        .await?;
        Ok(())
    }
}

pub async fn dev_fed(process_mgr: &ProcessManager) -> Result<DevFed> {
    let start_time = fedimint_core::time::now();
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let ((cln, lnd, gw_cln, gw_lnd), electrs, esplora, fed) = tokio::try_join!(
        async {
            let (cln, lnd) = tokio::try_join!(
                Lightningd::new(process_mgr, bitcoind.clone()),
                Lnd::new(process_mgr, bitcoind.clone())
            )?;
            info!(LOG_DEVIMINT, "lightning started");
            let (gw_cln, gw_lnd, _) = tokio::try_join!(
                Gatewayd::new(process_mgr, LightningNode::Cln(cln.clone())),
                Gatewayd::new(process_mgr, LightningNode::Lnd(lnd.clone())),
                open_channel(process_mgr, &bitcoind, &cln, &lnd),
            )?;
            info!(LOG_DEVIMINT, "gateways started");
            Ok((cln, lnd, gw_cln, gw_lnd))
        },
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
        async {
            let fed_size = process_mgr.globals.FM_FED_SIZE;
            Federation::new(process_mgr, bitcoind.clone(), fed_size).await
        },
    )?;
    info!(LOG_DEVIMINT, "federation and gateways started");
    tokio::try_join!(gw_cln.connect_fed(&fed), gw_lnd.connect_fed(&fed))?;
    // Initialize fedimint-cli
    cmd!(fed, "join-federation", fed.invite_code()?)
        .run()
        .await?;
    info!(LOG_DEVIMINT, "await gateways registered");
    fed.await_gateways_registered().await?;
    info!(LOG_DEVIMINT, "gateways registered");
    fed.use_gateway(&gw_cln).await?;
    info!(
        LOG_DEVIMINT,
        "starting dev federation took {:?}",
        start_time.elapsed()?
    );
    Ok(DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        electrs,
        esplora,
    })
}
