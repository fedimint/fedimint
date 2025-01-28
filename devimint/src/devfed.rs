use std::ops::Deref as _;
use std::sync::Arc;

use anyhow::Result;
use fedimint_core::runtime;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_logging::LOG_DEVIMINT;
use tokio::join;
use tracing::{debug, info};

use crate::external::{
    open_channel, open_channels_between_gateways, Bitcoind, Electrs, Esplora, Lightningd, Lnd,
    NamedGateway,
};
use crate::federation::{Client, Federation};
use crate::gatewayd::Gatewayd;
use crate::util::ProcessManager;
use crate::version_constants::VERSION_0_6_0_ALPHA;
use crate::LightningNode;

async fn spawn_drop<T>(t: T)
where
    T: Send + 'static,
{
    runtime::spawn("spawn_drop", async {
        drop(t);
    })
    .await
    .expect("drop panic");
}

#[derive(Clone)]
pub struct DevFed {
    pub bitcoind: Bitcoind,
    pub cln: Lightningd,
    pub lnd: Lnd,
    pub fed: Federation,
    pub gw_lnd: Gatewayd,
    pub gw_ldk: Gatewayd,
    pub electrs: Electrs,
    pub esplora: Esplora,
}

impl DevFed {
    pub async fn fast_terminate(self) {
        let Self {
            bitcoind,
            cln,
            lnd,
            fed,
            gw_lnd,
            gw_ldk,
            electrs,
            esplora,
        } = self;

        join!(
            spawn_drop(gw_lnd),
            spawn_drop(gw_ldk),
            spawn_drop(fed),
            spawn_drop(lnd),
            spawn_drop(cln),
            spawn_drop(esplora),
            spawn_drop(electrs),
            spawn_drop(bitcoind),
        );
    }
}
pub async fn dev_fed(process_mgr: &ProcessManager) -> Result<DevFed> {
    DevJitFed::new(process_mgr, false)
        .await?
        .to_dev_fed(process_mgr)
        .await
}

type JitArc<T> = JitTryAnyhow<Arc<T>>;

#[derive(Clone)]
pub struct DevJitFed {
    bitcoind: JitArc<Bitcoind>,
    cln: JitArc<Lightningd>,
    lnd: JitArc<Lnd>,
    fed: JitArc<Federation>,
    gw_lnd: JitArc<Gatewayd>,
    gw_ldk: JitArc<Gatewayd>,
    electrs: JitArc<Electrs>,
    esplora: JitArc<Esplora>,
    start_time: std::time::SystemTime,
    gw_lnd_registered: JitArc<()>,
    gw_ldk_connected: JitArc<()>,
    fed_epoch_generated: JitArc<()>,
    channel_opened: JitArc<()>,
}

impl DevJitFed {
    pub async fn new(process_mgr: &ProcessManager, skip_setup: bool) -> Result<DevJitFed> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );
        let start_time = fedimint_core::time::now();

        debug!("Starting dev federation");

        let bitcoind = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            move || async move {
                debug!(target: LOG_DEVIMINT, "Starting bitcoind...");
                let start_time = fedimint_core::time::now();
                let bitcoind = Bitcoind::new(&process_mgr, skip_setup).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started bitcoind");
                Ok(Arc::new(bitcoind))
            }
        });
        let cln = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting cln...");
                let start_time = fedimint_core::time::now();
                let lightningd = Lightningd::new(&process_mgr, bitcoind).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started cln");
                Ok(Arc::new(lightningd))
            }
        });
        let lnd = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting lnd...");
                let start_time = fedimint_core::time::now();
                let lnd = Lnd::new(&process_mgr, bitcoind).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started lnd");
                Ok(Arc::new(lnd))
            }
        });
        let electrs = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting electrs...");
                let start_time = fedimint_core::time::now();
                let electrs = Electrs::new(&process_mgr, bitcoind).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started electrs");
                Ok(Arc::new(electrs))
            }
        });
        let esplora = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting esplora...");
                let start_time = fedimint_core::time::now();
                let esplora = Esplora::new(&process_mgr, bitcoind).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started esplora");
                Ok(Arc::new(esplora))
            }
        });

        let fed = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting federation...");
                let start_time = fedimint_core::time::now();
                let mut fed = Federation::new(
                    &process_mgr,
                    bitcoind,
                    fed_size,
                    skip_setup,
                    "default".to_string(),
                )
                .await?;

                // Create a degraded federation if there are offline nodes
                fed.degrade_federation(&process_mgr).await?;

                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started federation");

                Ok(Arc::new(fed))
            }
        });

        let gw_lnd = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            || async move {
                let lnd = lnd.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Starting lnd gateway...");
                let start_time = fedimint_core::time::now();
                let lnd_gw = Gatewayd::new(&process_mgr, LightningNode::Lnd(lnd)).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started lnd gateway");
                Ok(Arc::new(lnd_gw))
            }
        });
        let gw_lnd_registered = JitTryAnyhow::new_try({
            let gw_lnd = gw_lnd.clone();
            let fed = fed.clone();
            move || async move {
                let gw_lnd = gw_lnd.get_try().await?.deref();
                let fed = fed.get_try().await?.deref();
                debug!(target: LOG_DEVIMINT, "Registering lnd gateway...");
                let start_time = fedimint_core::time::now();
                if !skip_setup {
                    gw_lnd.connect_fed(fed).await?;
                }
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Registered lnd gateway");
                Ok(Arc::new(()))
            }
        });

        /*
        let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
        let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        let should_enable_ldk = gatewayd_version >= *VERSION_0_5_0_ALPHA
                    && fedimintd_version >= *VERSION_0_5_0_ALPHA
                    // and lnv2 was not explicitly disabled
                    && !is_env_var_set(FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV);
        let should_disable_lnv2 = gateway_cli_version <= *VERSION_0_4_0_ALPHA
            || gatewayd_version <= *VERSION_0_4_0_ALPHA
            || fedimintd_version <= *VERSION_0_4_0_ALPHA
            || is_env_var_set(FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV)
            || !should_enable_ldk;
        */

        let gw_ldk = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            move || async move {
                debug!(target: LOG_DEVIMINT, "Starting ldk gateway...");
                let start_time = fedimint_core::time::now();
                let ldk_gw = Gatewayd::new(&process_mgr, LightningNode::Ldk).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started ldk gateway");
                Ok(Arc::new(ldk_gw))
            }
        });

        let gw_ldk_connected = JitTryAnyhow::new_try({
            let gw_ldk = gw_ldk.clone();
            let fed = fed.clone();
            move || async move {
                let gw_ldk = gw_ldk.get_try().await?.deref();
                // Only connect to the federation if LNv2 is active
                let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
                if gatewayd_version >= *VERSION_0_6_0_ALPHA {
                    let fed = fed.get_try().await?.deref();
                    debug!(target: LOG_DEVIMINT, "Registering ldk gateway...");
                    let start_time = fedimint_core::time::now();
                    if !skip_setup {
                        gw_ldk.connect_fed(fed).await?;
                    }
                    info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "LDK Gateway connected to federation");
                    Ok(Arc::new(()))
                } else {
                    Err(anyhow::anyhow!("Cannot connect LDK gateway to federation"))
                }
            }
        });

        let channel_opened = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            let gw_lnd = gw_lnd.clone();
            let cln = cln.clone();
            let gw_ldk = gw_ldk.clone();
            let bitcoind = bitcoind.clone();
            move || async move {
                // Note: We open new channel even if starting from existing state
                // as ports change on every start, and without this nodes will not find each
                // other.

                let bitcoind = bitcoind.get_try().await?.deref().clone();

                tokio::try_join!(
                    async {
                        let gw_lnd = gw_lnd.get_try().await?.deref();
                        let gw_ldk = gw_ldk.get_try().await?.deref();
                        let gateways: &[NamedGateway<'_>] = &[(gw_lnd, "LND"), (gw_ldk, "LDK")];

                        debug!(target: LOG_DEVIMINT, "Opening channels between gateways...");
                        let start_time = fedimint_core::time::now();
                        let res = open_channels_between_gateways(&bitcoind, gateways).await;
                        info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Opened channels between gateways");
                        res
                    },
                    async {
                        let lnd = lnd.get_try().await?.deref().clone();
                        let cln = cln.get_try().await?.deref().clone();

                        debug!(target: LOG_DEVIMINT, "Opening channels between cln and lnd...");
                        let start_time = fedimint_core::time::now();
                        let res = open_channel(&process_mgr, &bitcoind, &cln, &lnd).await;
                        info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Opened channels between cln and lnd");
                        res
                    }
                )?;

                Ok(Arc::new(()))
            }
        });

        let fed_epoch_generated = JitTryAnyhow::new_try({
            let fed = fed.clone();
            move || async move {
                let fed = fed.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Generating federation epoch...");
                let start_time = fedimint_core::time::now();
                if !skip_setup {
                    fed.mine_then_wait_blocks_sync(10).await?;
                }
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Generated federation epoch");
                Ok(Arc::new(()))
            }
        });

        Ok(DevJitFed {
            bitcoind,
            cln,
            lnd,
            fed,
            gw_lnd,
            gw_ldk,
            electrs,
            esplora,
            start_time,
            gw_lnd_registered,
            gw_ldk_connected,
            fed_epoch_generated,
            channel_opened,
        })
    }

    pub async fn electrs(&self) -> anyhow::Result<&Electrs> {
        Ok(self.electrs.get_try().await?.deref())
    }
    pub async fn esplora(&self) -> anyhow::Result<&Esplora> {
        Ok(self.esplora.get_try().await?.deref())
    }
    pub async fn cln(&self) -> anyhow::Result<&Lightningd> {
        Ok(self.cln.get_try().await?.deref())
    }
    pub async fn lnd(&self) -> anyhow::Result<&Lnd> {
        Ok(self.lnd.get_try().await?.deref())
    }
    pub async fn gw_lnd(&self) -> anyhow::Result<&Gatewayd> {
        Ok(self.gw_lnd.get_try().await?.deref())
    }
    pub async fn gw_lnd_registered(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_lnd_registered.get_try().await?;
        Ok(self.gw_lnd.get_try().await?.deref())
    }
    pub async fn gw_ldk(&self) -> anyhow::Result<&Gatewayd> {
        Ok(self.gw_ldk.get_try().await?.deref())
    }
    pub async fn gw_ldk_connected(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_ldk_connected.get_try().await?;
        Ok(self.gw_ldk.get_try().await?.deref())
    }
    pub async fn fed(&self) -> anyhow::Result<&Federation> {
        Ok(self.fed.get_try().await?.deref())
    }
    pub async fn bitcoind(&self) -> anyhow::Result<&Bitcoind> {
        Ok(self.bitcoind.get_try().await?.deref())
    }

    pub async fn internal_client(&self) -> anyhow::Result<Client> {
        Ok(self.fed().await?.internal_client().await?.clone())
    }

    /// Like [`Self::internal_client`] but will check and wait for a LN gateway
    /// to be registered
    pub async fn internal_client_gw_registered(&self) -> anyhow::Result<Client> {
        self.fed().await?.await_gateways_registered().await?;
        Ok(self.fed().await?.internal_client().await?.clone())
    }

    pub async fn finalize(&self, process_mgr: &ProcessManager) -> anyhow::Result<()> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );

        let _ = self.internal_client_gw_registered().await?;
        let _ = self.channel_opened.get_try().await?;
        let _ = self.gw_lnd_registered().await?;
        let _ = self.gw_ldk_connected().await?;
        let _ = self.cln().await?;
        let _ = self.lnd().await?;
        let _ = self.electrs().await?;
        let _ = self.esplora().await?;
        let _ = self.fed_epoch_generated.get_try().await?;

        debug!(
            target: LOG_DEVIMINT,
            fed_size,
            offline_nodes,
            elapsed_ms = %self.start_time.elapsed()?.as_millis(),
            "Dev federation ready",
        );
        Ok(())
    }

    pub async fn to_dev_fed(self, process_mgr: &ProcessManager) -> anyhow::Result<DevFed> {
        self.finalize(process_mgr).await?;
        Ok(DevFed {
            bitcoind: self.bitcoind().await?.to_owned(),
            cln: self.cln().await?.to_owned(),
            lnd: self.lnd().await?.to_owned(),
            fed: self.fed().await?.to_owned(),
            gw_lnd: self.gw_lnd().await?.to_owned(),
            gw_ldk: self.gw_ldk().await?.to_owned(),
            esplora: self.esplora().await?.to_owned(),
            electrs: self.electrs().await?.to_owned(),
        })
    }

    pub async fn fast_terminate(self) {
        let Self {
            bitcoind,
            cln,
            lnd,
            fed,
            gw_lnd,
            electrs,
            esplora,
            ..
        } = self;

        join!(
            spawn_drop(gw_lnd),
            spawn_drop(fed),
            spawn_drop(lnd),
            spawn_drop(cln),
            spawn_drop(esplora),
            spawn_drop(electrs),
            spawn_drop(bitcoind),
        );
    }
}
