use std::ops::Deref as _;
use std::sync::Arc;

use anyhow::Result;
use fedimint_core::envs::{is_env_var_set, FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV};
use fedimint_core::runtime;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_logging::LOG_DEVIMINT;
use tokio::join;
use tracing::debug;

use crate::external::{
    open_channel, open_channels_between_gateways, Bitcoind, Electrs, Esplora, Lightningd, Lnd,
    NamedGateway,
};
use crate::federation::{Client, Federation};
use crate::gatewayd::Gatewayd;
use crate::util::ProcessManager;
use crate::version_constants::{VERSION_0_4_0_ALPHA, VERSION_0_5_0_ALPHA};
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
    pub gw_cln: Gatewayd,
    pub gw_lnd: Gatewayd,
    pub gw_ldk: Option<Gatewayd>,
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
            gw_cln,
            gw_lnd,
            gw_ldk,
            electrs,
            esplora,
        } = self;

        join!(
            spawn_drop(gw_cln),
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
    DevJitFed::new(process_mgr, false)?
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
    gw_cln: JitArc<Gatewayd>,
    gw_lnd: JitArc<Gatewayd>,
    gw_ldk: JitArc<Option<Gatewayd>>,
    electrs: JitArc<Electrs>,
    esplora: JitArc<Esplora>,
    start_time: std::time::SystemTime,
    gw_cln_registered: JitArc<()>,
    gw_lnd_registered: JitArc<()>,
    gw_ldk_connected: JitArc<()>,
    fed_epoch_generated: JitArc<()>,
    channel_opened: JitArc<()>,
}

impl DevJitFed {
    pub fn new(process_mgr: &ProcessManager, skip_setup: bool) -> Result<DevJitFed> {
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
            move || async move { Ok(Arc::new(Bitcoind::new(&process_mgr, skip_setup).await?)) }
        });
        let cln = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                Ok(Arc::new(
                    Lightningd::new(&process_mgr, bitcoind.get_try().await?.deref().clone())
                        .await?,
                ))
            }
        });
        let lnd = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                Ok(Arc::new(
                    Lnd::new(&process_mgr, bitcoind.get_try().await?.deref().clone()).await?,
                ))
            }
        });
        let electrs = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                Ok(Arc::new(Electrs::new(&process_mgr, bitcoind).await?))
            }
        });
        let esplora = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                Ok(Arc::new(Esplora::new(&process_mgr, bitcoind).await?))
            }
        });

        let fed = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
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

                Ok(Arc::new(fed))
            }
        });

        let gw_cln = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let cln = cln.clone();
            || async move {
                let cln = cln.get_try().await?.deref().clone();
                Ok(Arc::new(
                    Gatewayd::new(&process_mgr, LightningNode::Cln(cln)).await?,
                ))
            }
        });
        let gw_cln_registered = JitTryAnyhow::new_try({
            let gw_cln = gw_cln.clone();
            let fed = fed.clone();
            move || async move {
                let gw_cln = gw_cln.get_try().await?.deref();
                let fed = fed.get_try().await?.deref();

                if !skip_setup {
                    gw_cln.connect_fed(fed).await?;
                }
                Ok(Arc::new(()))
            }
        });
        let gw_lnd = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            || async move {
                let lnd = lnd.get_try().await?.deref().clone();
                Ok(Arc::new(
                    Gatewayd::new(&process_mgr, LightningNode::Lnd(lnd)).await?,
                ))
            }
        });
        let gw_lnd_registered = JitTryAnyhow::new_try({
            let gw_lnd = gw_lnd.clone();
            let fed = fed.clone();
            move || async move {
                let gw_lnd = gw_lnd.get_try().await?.deref();
                let fed = fed.get_try().await?.deref();
                if !skip_setup {
                    gw_lnd.connect_fed(fed).await?;
                }
                Ok(Arc::new(()))
            }
        });
        let gw_ldk = JitTryAnyhow::new_try({
            let esplora = esplora.clone();
            let process_mgr = process_mgr.to_owned();
            move || async move {
                // TODO(support:v0.4.0): Only run LDK gateway when the federation supports LNv2
                let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
                let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
                if gatewayd_version >= *VERSION_0_5_0_ALPHA
                    && fedimintd_version >= *VERSION_0_5_0_ALPHA
                    // and lnv2 was not explicitly disabled
                    && !is_env_var_set(FM_DEVIMINT_DISABLE_MODULE_LNV2_ENV)
                {
                    esplora.get_try().await?;
                    Ok(Arc::new(Some(
                        Gatewayd::new(&process_mgr, LightningNode::Ldk).await?,
                    )))
                } else {
                    Ok(Arc::new(None))
                }
            }
        });
        let gw_ldk_connected = JitTryAnyhow::new_try({
            let gw_ldk = gw_ldk.clone();
            let fed = fed.clone();
            move || async move {
                let gw_ldk = gw_ldk.get_try().await?.deref();
                if let Some(gw_ldk) = gw_ldk {
                    let fed = fed.get_try().await?.deref();
                    if !skip_setup {
                        gw_ldk.connect_fed(fed).await?;
                    }
                }
                Ok(Arc::new(()))
            }
        });

        let channel_opened = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            let gw_lnd = gw_lnd.clone();
            let cln = cln.clone();
            let gw_cln = gw_cln.clone();
            let gw_ldk = gw_ldk.clone();
            let bitcoind = bitcoind.clone();
            || async move {
                // Note: We open new channel even if starting from existing state
                // as ports change on every start, and without this nodes will not find each
                // other.

                let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
                let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
                let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;

                let bitcoind = bitcoind.get_try().await?.deref().clone();

                if gateway_cli_version < *VERSION_0_4_0_ALPHA
                    || gatewayd_version < *VERSION_0_4_0_ALPHA
                    || fedimintd_version < *VERSION_0_4_0_ALPHA
                {
                    let lnd = lnd.get_try().await?.deref().clone();
                    let cln = cln.get_try().await?.deref().clone();

                    open_channel(&process_mgr, &bitcoind, &cln, &lnd).await?;
                } else {
                    let gw_cln = gw_cln.get_try().await?.deref();
                    let gw_lnd = gw_lnd.get_try().await?.deref();

                    let gateways: &[NamedGateway<'_>] =
                        if let Some(gw_ldk) = gw_ldk.get_try().await?.deref() {
                            &[(gw_cln, "CLN"), (gw_lnd, "LND"), (gw_ldk, "LDK")]
                        } else {
                            &[(gw_cln, "CLN"), (gw_lnd, "LND")]
                        };

                    open_channels_between_gateways(&bitcoind, gateways).await?;
                }

                Ok(Arc::new(()))
            }
        });

        let fed_epoch_generated = JitTryAnyhow::new_try({
            let fed = fed.clone();
            move || async move {
                let fed = fed.get_try().await?.deref().clone();
                if !skip_setup {
                    fed.mine_then_wait_blocks_sync(10).await?;
                }
                Ok(Arc::new(()))
            }
        });

        Ok(DevJitFed {
            bitcoind,
            cln,
            lnd,
            fed,
            gw_cln,
            gw_lnd,
            gw_ldk,
            electrs,
            esplora,
            start_time,
            gw_cln_registered,
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
    pub async fn gw_cln(&self) -> anyhow::Result<&Gatewayd> {
        Ok(self.gw_cln.get_try().await?.deref())
    }
    pub async fn gw_cln_registered(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_cln_registered.get_try().await?;
        Ok(self.gw_cln.get_try().await?.deref())
    }
    pub async fn gw_lnd(&self) -> anyhow::Result<&Gatewayd> {
        Ok(self.gw_lnd.get_try().await?.deref())
    }
    pub async fn gw_lnd_registered(&self) -> anyhow::Result<&Gatewayd> {
        self.gw_lnd_registered.get_try().await?;
        Ok(self.gw_lnd.get_try().await?.deref())
    }
    pub async fn gw_ldk(&self) -> anyhow::Result<&Option<Gatewayd>> {
        Ok(self.gw_ldk.get_try().await?.deref())
    }
    pub async fn gw_ldk_connected(&self) -> anyhow::Result<&Option<Gatewayd>> {
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
        let _ = self.gw_cln_registered().await?;
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
            gw_cln: self.gw_cln().await?.to_owned(),
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
            gw_cln,
            gw_lnd,
            electrs,
            esplora,
            ..
        } = self;

        join!(
            spawn_drop(gw_cln),
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
