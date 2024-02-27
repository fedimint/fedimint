use anyhow::Result;
use fedimint_logging::LOG_DEVIMINT;
use tracing::info;

use crate::external::{open_channel_with_ldk, Bitcoind, Electrs, Esplora, Lightningd, Lnd};
use crate::federation::Federation;
use crate::gatewayd::Gatewayd;
use crate::util::ProcessManager;
use crate::{cmd, open_channel, LightningNode};

#[derive(Clone)]
pub struct DevFed {
    pub bitcoind: Bitcoind,
    pub cln: Lightningd,
    pub lnd: Lnd,
    pub fed: Federation,
    pub gw_cln: Gatewayd,
    pub gw_lnd: Gatewayd,
    pub gw_ldk: Gatewayd,
    pub electrs: Electrs,
    pub esplora: Esplora,
}

pub async fn dev_fed(process_mgr: &ProcessManager) -> Result<DevFed> {
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
    anyhow::ensure!(
        fed_size > 3 * offline_nodes,
        "too many offline nodes ({offline_nodes}) to reach consensus"
    );

    let start_time = fedimint_core::time::now();
    let bitcoind = Bitcoind::new(process_mgr).await?;
    let ((cln, lnd, gw_cln, gw_lnd, gw_ldk), electrs, esplora, mut fed) = tokio::try_join!(
        async {
            let (cln, lnd) = tokio::try_join!(
                Lightningd::new(process_mgr, bitcoind.clone()),
                Lnd::new(process_mgr, bitcoind.clone())
            )?;
            info!(target: LOG_DEVIMINT, "lightning started");
            let (gw_cln, gw_lnd, gw_ldk, _) = tokio::try_join!(
                Gatewayd::new(process_mgr, LightningNode::Cln(cln.clone())),
                Gatewayd::new(process_mgr, LightningNode::Lnd(lnd.clone())),
                Gatewayd::new(process_mgr, LightningNode::Ldk),
                open_channel(process_mgr, &bitcoind, &cln, &lnd),
            )?;
            info!(target: LOG_DEVIMINT, "gateways started");
            Ok((cln, lnd, gw_cln, gw_lnd, gw_ldk))
        },
        Electrs::new(process_mgr, bitcoind.clone()),
        Esplora::new(process_mgr, bitcoind.clone()),
        Federation::new(process_mgr, bitcoind.clone(), fed_size),
    )?;
    // open_channel_with_ldk(process_mgr, &bitcoind, &lnd)
    //     .await
    //     .unwrap();

    // Send a coin to LDK wallet.
    // bitcoind
    //     .send_to(
    //         String::from("
    // 03c964ca4d2eed93720809be7c8779ed602f80ba308e474d03bcb81b9bad807477"),
    //         100_000_000,
    //     )
    //     .await?;
    bitcoind.mine_blocks(10).await?;

    info!(target: LOG_DEVIMINT, "federation and gateways started");

    tokio::try_join!(
        gw_cln.connect_fed(&fed),
        gw_lnd.connect_fed(&fed),
        gw_ldk.connect_fed(&fed),
        async {
            info!(target: LOG_DEVIMINT, "Joining federation with the main client");
            cmd!(fed.internal_client(), "join-federation", fed.invite_code()?)
                .run()
                .await?;
            info!(target: LOG_DEVIMINT, "Generating first epoch");
            fed.mine_then_wait_blocks_sync(10).await?;
            Ok(())
        }
    )?;

    // Initialize fedimint-cli
    info!(target: LOG_DEVIMINT, "await gateways registered");
    fed.await_gateways_registered().await?;
    info!(target: LOG_DEVIMINT, "gateways registered");

    // Create a degraded federation if there are offline nodes
    fed.degrade_federation(process_mgr).await?;

    info!(
        target: LOG_DEVIMINT,
        fed_size,
        offline_nodes,
        "finished creating dev federation, took {:?}",
        start_time.elapsed()?
    );

    Ok(DevFed {
        bitcoind,
        cln,
        lnd,
        fed,
        gw_cln,
        gw_lnd,
        gw_ldk,
        electrs,
        esplora,
    })
}
