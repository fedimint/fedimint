use devimint::util;
use fedimint_lnv2_client::FinalSendOperationState;
use tracing::info;

#[path = "common.rs"]
mod common;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            if !util::supports_lnv2() {
                info!("lnv2 is disabled, skipping");
                return Ok(());
            }

            let federation = dev_fed.fed().await?;

            let client = federation
                .new_joined_client("lnv1-lnv2-swap-test-client")
                .await?;

            federation.pegin_client(10_000, &client).await?;

            let gw_lnd = dev_fed.gw_lnd().await?;

            info!("Pegging-in gateway...");
            federation.pegin_gateways(1_000_000, vec![gw_lnd]).await?;

            info!("Testing LNv1 client can pay LNv2 invoice...");
            let lnd_gw_id = gw_lnd.gateway_id.clone();
            let (invoice, receive_op) = common::receive(&client, &gw_lnd.addr, 1_000_000).await?;
            common::send_lnv1(&client, &lnd_gw_id, &invoice.to_string()).await?;
            common::await_receive_claimed(&client, receive_op).await?;

            info!("Testing LNv2 client can pay LNv1 invoice...");
            let (invoice, receive_op) =
                common::receive_lnv1(&client, &lnd_gw_id, 1_000_000).await?;
            let state = common::send(&client, &gw_lnd.addr, &invoice.to_string()).await?;
            assert!(matches!(state, FinalSendOperationState::Success(_)));
            common::await_receive_lnv1(&client, receive_op).await?;

            info!("LNv1 <-> LNv2 swap tests complete!");

            Ok(())
        })
        .await
}
