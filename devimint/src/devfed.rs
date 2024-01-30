use anyhow::Result;
use fedimint_logging::LOG_DEVIMINT;
use tracing::info;

use crate::external::{Bitcoind, Electrs, Esplora, Lightningd, Lnd};
use crate::federation::Federation;
use crate::gatewayd::Gatewayd;
use crate::util::ProcessManager;
use crate::{cmd, open_channel, LightningNode};

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
    let start_time = fedimint_core::time::now();
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let ((cln, lnd, gw_cln, gw_lnd), electrs, esplora, fed) = tokio::try_join!(
        async {
            let (cln, lnd) = tokio::try_join!(
                Lightningd::new(process_mgr, bitcoind.clone()),
                Lnd::new(process_mgr, bitcoind.clone())
            )?;
            info!(target: LOG_DEVIMINT, "lightning started");
            let (gw_cln, gw_lnd, _) = tokio::try_join!(
                Gatewayd::new(process_mgr, LightningNode::Cln(cln.clone())),
                Gatewayd::new(process_mgr, LightningNode::Lnd(lnd.clone())),
                open_channel(process_mgr, &bitcoind, &cln, &lnd),
            )?;
            info!(target: LOG_DEVIMINT, "gateways started");
            Ok((cln, lnd, gw_cln, gw_lnd))
        },
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
        async {
            let fed_size = process_mgr.globals.FM_FED_SIZE;
            Federation::new(process_mgr, bitcoind.clone(), fed_size).await
        },
    )?;

    info!(target: LOG_DEVIMINT, "federation and gateways started");

    tokio::try_join!(gw_cln.connect_fed(&fed), gw_lnd.connect_fed(&fed), async {
        info!(target: LOG_DEVIMINT, "Joining federation with the main client");
        cmd!(fed.internal_client(), "join-federation", fed.invite_code()?)
            .run()
            .await?;
        info!(target: LOG_DEVIMINT, "Generating first epoch");
        fed.mine_then_wait_blocks_sync(10).await?;
        Ok(())
    })?;

    // Initialize fedimint-cli
    info!(target: LOG_DEVIMINT, "await gateways registered");
    fed.await_gateways_registered().await?;
    info!(target: LOG_DEVIMINT, "gateways registered");
    info!(
        target: LOG_DEVIMINT,
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
