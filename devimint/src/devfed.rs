use std::ops::Deref as _;
use std::sync::Arc;

use anyhow::Result;
use fedimint_core::runtime;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_logging::LOG_DEVIMINT;
use tokio::join;
use tracing::{debug, info};

use crate::LightningNode;
use crate::external::{Bitcoind, Esplora, Lnd, NamedGateway, open_channels_between_gateways};
use crate::federation::{Client, Federation};
use crate::gatewayd::Gatewayd;
use crate::recurringd::Recurringd;
use crate::recurringdv2::Recurringdv2;
use crate::util::{ProcessManager, supports_lnv2};

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
    pub lnd: Lnd,
    pub fed: Federation,
    pub gw_lnd: Gatewayd,
    pub gw_ldk: Gatewayd,
    pub gw_ldk_second: Gatewayd,
    pub esplora: Esplora,
    pub recurringd: Recurringd,
    pub recurringdv2: Recurringdv2,
}

impl DevFed {
    pub async fn fast_terminate(self) {
        let Self {
            bitcoind,
            lnd,
            fed,
            gw_lnd,
            gw_ldk,
            gw_ldk_second,
            esplora,
            recurringd,
            recurringdv2,
        } = self;

        join!(
            spawn_drop(gw_lnd),
            spawn_drop(gw_ldk),
            spawn_drop(gw_ldk_second),
            spawn_drop(fed),
            spawn_drop(lnd),
            spawn_drop(esplora),
            spawn_drop(bitcoind),
            spawn_drop(recurringd),
            spawn_drop(recurringdv2),
        );
    }
}
pub async fn dev_fed(process_mgr: &ProcessManager) -> Result<DevFed> {
    DevJitFed::new(process_mgr, false, false)?
        .to_dev_fed(process_mgr)
        .await
}

type JitArc<T> = JitTryAnyhow<Arc<T>>;

#[derive(Clone)]
pub struct DevJitFed {
    bitcoind: JitArc<Bitcoind>,
    lnd: JitArc<Lnd>,
    fed: JitArc<Federation>,
    gw_lnd: JitArc<Gatewayd>,
    gw_ldk: JitArc<Gatewayd>,
    gw_ldk_second: JitArc<Gatewayd>,
    esplora: JitArc<Esplora>,
    recurringd: JitArc<Recurringd>,
    recurringdv2: JitArc<Recurringdv2>,
    start_time: std::time::SystemTime,
    gw_lnd_registered: JitArc<()>,
    gw_ldk_connected: JitArc<()>,
    gw_ldk_second_connected: JitArc<()>,
    fed_epoch_generated: JitArc<()>,
    channel_opened: JitArc<()>,
    recurringd_connected: JitArc<()>,

    skip_setup: bool,
    pre_dkg: bool,
}

impl DevJitFed {
    pub fn new(process_mgr: &ProcessManager, skip_setup: bool, pre_dkg: bool) -> Result<DevJitFed> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );
        let start_time = fedimint_core::time::now();

        debug!(target: LOG_DEVIMINT, %fed_size, %offline_nodes, "Starting dev federation");

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
                    skip_setup,
                    pre_dkg,
                    0,
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
                let lnd_gw = Gatewayd::new(&process_mgr, LightningNode::Lnd(lnd), 0).await?;
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
                if !skip_setup && !pre_dkg {
                    gw_lnd.connect_fed(fed).await?;
                }
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Registered lnd gateway");
                Ok(Arc::new(()))
            }
        });

        let gw_ldk = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                bitcoind.get_try().await?;
                debug!(target: LOG_DEVIMINT, "Starting ldk gateway...");
                let start_time = fedimint_core::time::now();
                let ldk_gw = Gatewayd::new(
                    &process_mgr,
                    LightningNode::Ldk {
                        name: "gatewayd-ldk-0".to_string(),
                        gw_port: process_mgr.globals.FM_PORT_GW_LDK,
                        ldk_port: process_mgr.globals.FM_PORT_LDK,
                        metrics_port: process_mgr.globals.FM_PORT_GW_LDK_METRICS,
                    },
                    1,
                )
                .await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started ldk gateway");
                Ok(Arc::new(ldk_gw))
            }
        });
        let gw_ldk_second = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                bitcoind.get_try().await?;
                debug!(target: LOG_DEVIMINT, "Starting ldk gateway 2...");
                let start_time = fedimint_core::time::now();
                let ldk_gw2 = Gatewayd::new(
                    &process_mgr,
                    LightningNode::Ldk {
                        name: "gatewayd-ldk-1".to_string(),
                        gw_port: process_mgr.globals.FM_PORT_GW_LDK2,
                        ldk_port: process_mgr.globals.FM_PORT_LDK2,
                        metrics_port: process_mgr.globals.FM_PORT_GW_LDK2_METRICS,
                    },
                    2,
                )
                .await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started ldk gateway 2");
                Ok(Arc::new(ldk_gw2))
            }
        });
        let gw_ldk_connected = JitTryAnyhow::new_try({
            let gw_ldk = gw_ldk.clone();
            let fed = fed.clone();
            move || async move {
                let gw_ldk = gw_ldk.get_try().await?.deref();
                if supports_lnv2() {
                    let fed = fed.get_try().await?.deref();
                    let start_time = fedimint_core::time::now();
                    if !skip_setup && !pre_dkg {
                        debug!(target: LOG_DEVIMINT, "Registering ldk gateway...");
                        gw_ldk.connect_fed(fed).await?;
                    } else {
                        debug!(target: LOG_DEVIMINT, "Skipping registering ldk gateway");
                    }
                    info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Connected ldk gateway");
                }
                Ok(Arc::new(()))
            }
        });
        let gw_ldk_second_connected = JitTryAnyhow::new_try({
            let gw_ldk_second = gw_ldk_second.clone();
            let fed = fed.clone();
            move || async move {
                let gw_ldk2 = gw_ldk_second.get_try().await?.deref();
                if supports_lnv2() {
                    let fed = fed.get_try().await?.deref();
                    debug!(target: LOG_DEVIMINT, "Registering ldk gateway 2...");
                    let start_time = fedimint_core::time::now();
                    if !skip_setup && !pre_dkg {
                        gw_ldk2.connect_fed(fed).await?;
                    }
                    info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Connected ldk gateway 2");
                }
                Ok(Arc::new(()))
            }
        });

        let fed_epoch_generated = JitTryAnyhow::new_try({
            let fed = fed.clone();
            move || async move {
                let fed = fed.get_try().await?.deref().clone();
                debug!(target: LOG_DEVIMINT, "Generating federation epoch...");
                let start_time = fedimint_core::time::now();
                if !skip_setup && !pre_dkg {
                    fed.mine_then_wait_blocks_sync(10).await?;
                }
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Generated federation epoch");
                Ok(Arc::new(()))
            }
        });

        let channel_opened = JitTryAnyhow::new_try({
            let gw_lnd = gw_lnd.clone();
            let gw_ldk = gw_ldk.clone();
            let gw_ldk_second = gw_ldk_second.clone();
            let bitcoind = bitcoind.clone();
            let fed_epoch_generated = fed_epoch_generated.clone();
            move || async move {
                // Note: We open new channel even if starting from existing state
                // as ports change on every start, and without this nodes will not find each
                // other.
                let bitcoind = bitcoind.get_try().await?.deref().clone();

                // Wait for an epoch to occur since that mines blocks, which can cause opening
                // channels to be racy
                fed_epoch_generated.get_try().await?;

                let gw_ldk_second = gw_ldk_second.get_try().await?.deref();
                let gw_ldk = gw_ldk.get_try().await?.deref();
                let gw_lnd = gw_lnd.get_try().await?.deref();
                let gateways: &[NamedGateway<'_>] =
                    &[(gw_ldk_second, "LDK2"), (gw_lnd, "LND"), (gw_ldk, "LDK")];

                debug!(target: LOG_DEVIMINT, "Opening channels between gateways...");
                let start_time = fedimint_core::time::now();
                open_channels_between_gateways(&bitcoind, gateways).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Opened channels between gateways");

                Ok(Arc::new(()))
            }
        });

        let recurringd = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            move || async move {
                debug!(target: LOG_DEVIMINT, "Starting recurringd...");
                let start_time = fedimint_core::time::now();
                let recurringd = Recurringd::new(&process_mgr).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started recurringd");
                Ok(Arc::new(recurringd))
            }
        });

        let recurringd_connected = JitTryAnyhow::new_try({
            let recurringd = recurringd.clone();
            let fed = fed.clone();
            move || async move {
                let recurringd = recurringd.get_try().await?.deref();
                let fed = fed.get_try().await?.deref();
                debug!(target: LOG_DEVIMINT, "Connecting recurringd to federation...");
                let start_time = fedimint_core::time::now();
                if !skip_setup && !pre_dkg {
                    let invite_code = fed.invite_code()?;
                    recurringd.add_federation(&invite_code).await?;
                }
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Connected recurringd to federation");
                Ok(Arc::new(()))
            }
        });

        let recurringdv2 = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            move || async move {
                debug!(target: LOG_DEVIMINT, "Starting recurringdv2...");
                let start_time = fedimint_core::time::now();
                let recurringdv2 = Recurringdv2::new(&process_mgr).await?;
                info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed()?.as_millis(), "Started recurringdv2");
                Ok(Arc::new(recurringdv2))
            }
        });

        Ok(DevJitFed {
            bitcoind,
            lnd,
            fed,
            gw_lnd,
            gw_ldk,
            gw_ldk_second,
            esplora,
            recurringd,
            recurringdv2,
            start_time,
            gw_lnd_registered,
            gw_ldk_connected,
            gw_ldk_second_connected,
            fed_epoch_generated,
            channel_opened,
            recurringd_connected,
            skip_setup,
            pre_dkg,
        })
    }

    pub async fn esplora(&self) -> anyhow::Result<&Esplora> {
        Ok(self.esplora.get_try().await?.deref())
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
    pub async fn gw_ldk_second(&self) -> anyhow::Result<&Gatewayd> {
        Ok(self.gw_ldk_second.get_try().await?.deref())
    }
    pub async fn gw_ldk_connected(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_ldk_connected.get_try().await?;
        Ok(self.gw_ldk.get_try().await?.deref())
    }
    pub async fn gw_ldk_second_connected(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_ldk_second_connected.get_try().await?;
        Ok(self.gw_ldk_second.get_try().await?.deref())
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

    pub async fn recurringd(&self) -> anyhow::Result<&Recurringd> {
        Ok(self.recurringd.get_try().await?.deref())
    }

    pub async fn recurringd_connected(&self) -> anyhow::Result<&Recurringd> {
        self.recurringd_connected.get_try().await?;
        Ok(self.recurringd.get_try().await?.deref())
    }

    pub async fn recurringdv2(&self) -> anyhow::Result<&Recurringdv2> {
        Ok(self.recurringdv2.get_try().await?.deref())
    }

    pub async fn finalize(&self, process_mgr: &ProcessManager) -> anyhow::Result<()> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );

        if !self.pre_dkg && !self.skip_setup {
            let _ = self.internal_client_gw_registered().await?;
        }
        let _ = self.channel_opened.get_try().await?;
        let _ = self.gw_lnd_registered().await?;
        let _ = self.gw_ldk_connected().await?;
        let _ = self.gw_ldk_second_connected().await?;
        let _ = self.lnd().await?;
        let _ = self.esplora().await?;
        let _ = self.recurringd_connected().await?;
        let _ = self.recurringdv2().await?;
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
            lnd: self.lnd().await?.to_owned(),
            fed: self.fed().await?.to_owned(),
            gw_lnd: self.gw_lnd().await?.to_owned(),
            gw_ldk: self.gw_ldk().await?.to_owned(),
            gw_ldk_second: self.gw_ldk_second().await?.to_owned(),
            esplora: self.esplora().await?.to_owned(),
            recurringd: self.recurringd().await?.to_owned(),
            recurringdv2: self.recurringdv2().await?.to_owned(),
        })
    }

    pub async fn fast_terminate(self) {
        let Self {
            bitcoind,
            lnd,
            fed,
            gw_lnd,
            esplora,
            gw_ldk,
            gw_ldk_second,
            recurringd,
            recurringdv2,
            ..
        } = self;

        join!(
            spawn_drop(gw_lnd),
            spawn_drop(gw_ldk),
            spawn_drop(gw_ldk_second),
            spawn_drop(fed),
            spawn_drop(lnd),
            spawn_drop(esplora),
            spawn_drop(bitcoind),
            spawn_drop(recurringd),
            spawn_drop(recurringdv2),
        );
    }
}
