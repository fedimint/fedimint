use std::ops::Deref as _;
use std::sync::Arc;

use anyhow::Result;
use fedimint_core::task::jit::{JitTry, JitTryAnyhow};
use fedimint_logging::LOG_DEVIMINT;
use tracing::info;

use crate::envs::{FM_GWID_CLN_ENV, FM_GWID_LND_ENV};
use crate::external::{Bitcoind, Electrs, Esplora, Lightningd, Lnd};
use crate::federation::{Client, Federation};
use crate::gatewayd::Gatewayd;
use crate::util::ProcessManager;
use crate::{open_channel, LightningNode};

#[derive(Clone)]
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

pub async fn dev_fed(process_mgr: &ProcessManager) -> Result<DevFed> {
    DevJitFed::new(process_mgr)?.to_dev_fed(process_mgr).await
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
    electrs: JitArc<Electrs>,
    esplora: JitArc<Esplora>,
    start_time: std::time::SystemTime,
    gw_cln_registered: JitArc<()>,
    gw_lnd_registered: JitArc<()>,
    fed_epoch_generated: JitArc<()>,
    channel_opened: JitArc<()>,
}

impl DevJitFed {
    pub fn new(process_mgr: &ProcessManager) -> Result<DevJitFed> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );
        let start_time = fedimint_core::time::now();

        info!("Starting dev federation");

        let bitcoind = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            move || async move { Ok(Arc::new(Bitcoind::new(&process_mgr).await?)) }
        });
        let cln = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                Ok(Arc::new(
                    Lightningd::new(&process_mgr, bitcoind.get_try().await?.deref().clone())
                        .await?,
                ))
            }
        });
        let lnd = JitTry::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                Ok(Arc::new(
                    Lnd::new(&process_mgr, bitcoind.get_try().await?.deref().clone()).await?,
                ))
            }
        });
        let electrs = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                Ok(Arc::new(Electrs::new(&process_mgr, bitcoind).await?))
            }
        });
        let esplora = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                Ok(Arc::new(Esplora::new(&process_mgr, bitcoind).await?))
            }
        });

        let fed = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                let mut fed = Federation::new(&process_mgr, bitcoind, fed_size).await?;

                // Create a degraded federation if there are offline nodes
                fed.degrade_federation(&process_mgr).await?;

                Ok(Arc::new(fed))
            }
        });

        let gw_cln = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let cln = cln.clone();
            move || async move {
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

                gw_cln.connect_fed(fed).await?;
                Ok(Arc::new(()))
            }
        });
        let gw_lnd = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            move || async move {
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

                gw_lnd.connect_fed(fed).await?;
                Ok(Arc::new(()))
            }
        });

        let channel_opened = JitTryAnyhow::new_try({
            let process_mgr = process_mgr.to_owned();
            let lnd = lnd.clone();
            let cln = cln.clone();
            let bitcoind = bitcoind.clone();
            move || async move {
                let bitcoind = bitcoind.get_try().await?.deref().clone();
                let lnd = lnd.get_try().await?.deref().clone();
                let cln = cln.get_try().await?.deref().clone();
                open_channel(&process_mgr, &bitcoind, &cln, &lnd).await?;
                Ok(Arc::new(()))
            }
        });

        let fed_epoch_generated = JitTryAnyhow::new_try({
            let fed = fed.clone();
            move || async move {
                let fed = fed.get_try().await?.deref().clone();
                fed.mine_then_wait_blocks_sync(10).await?;
                Ok(Arc::new(()))
            }
        });

        Ok(DevJitFed {
            bitcoind,
            cln,
            lnd,
            fed,
            gw_cln,
            gw_cln_registered,
            gw_lnd,
            gw_lnd_registered,
            electrs,
            esplora,
            channel_opened,
            fed_epoch_generated,
            start_time,
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

        std::env::set_var(FM_GWID_CLN_ENV, self.gw_cln().await?.gateway_id().await?);
        std::env::set_var(FM_GWID_LND_ENV, self.gw_lnd().await?.gateway_id().await?);
        info!(target: LOG_DEVIMINT, "Setup gateway environment variables");

        let _ = self.internal_client_gw_registered().await?;
        let _ = self.channel_opened.get_try().await?;
        let _ = self.gw_cln_registered().await?;
        let _ = self.gw_lnd_registered().await?;
        let _ = self.cln().await?;
        let _ = self.lnd().await?;
        let _ = self.electrs().await?;
        let _ = self.esplora().await?;
        let _ = self.fed_epoch_generated.get_try().await?;

        info!(
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
            esplora: self.esplora().await?.to_owned(),
            electrs: self.electrs().await?.to_owned(),
        })
    }
}
