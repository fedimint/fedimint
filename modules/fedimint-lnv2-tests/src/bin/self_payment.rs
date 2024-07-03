use devimint::version_constants::VERSION_0_4_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_lnv2_client::{FinalReceiveState, FinalSendState};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let fedimintd_version = util::FedimintdCmd::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        if fedimint_cli_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimint_cli_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if fedimintd_version < *VERSION_0_4_0_ALPHA {
            info!(%fedimintd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        if gatewayd_version < *VERSION_0_4_0_ALPHA {
            info!(%gatewayd_version, "Version did not support lnv2 module, skipping");
            return Ok(());
        }

        let fed = dev_fed.fed().await?;

        // test self payment with one gateway

        let gw_lnd = dev_fed.gw_lnd().await?;

        let client = fed.new_joined_client("lnv2-module-client").await?;

        fed.pegin_client(10_000, &client).await?;

        fed.pegin_gateway(100_0000, gw_lnd).await?;

        let (invoice, receive_op) = serde_json::from_value::<(Bolt11Invoice, OperationId)>(
            cmd!(
                client,
                "module",
                "lnv2",
                "receive",
                gw_lnd.addr.clone(),
                "1000"
            )
            .out_json()
            .await?,
        )?;

        let send_op = serde_json::from_value::<OperationId>(
            cmd!(
                client,
                "module",
                "lnv2",
                "send",
                gw_lnd.addr.clone(),
                invoice.to_string()
            )
            .out_json()
            .await?,
        )?;

        assert_eq!(
            cmd!(
                client,
                "module",
                "lnv2",
                "await-send",
                serde_json::to_string(&send_op)?.substring(1, 65)
            )
            .out_json()
            .await?,
            serde_json::to_value(FinalSendState::Success).expect("JSON serialization failed"),
        );

        assert_eq!(
            cmd!(
                client,
                "module",
                "lnv2",
                "await-receive",
                serde_json::to_string(&receive_op)?.substring(1, 65)
            )
            .out_json()
            .await?,
            serde_json::to_value(FinalReceiveState::Claimed).expect("JSON serialization failed"),
        );

        // test self payment with two gateways

        let gw_cln = dev_fed.gw_cln().await?;

        fed.pegin_gateway(100_0000, gw_cln).await?;

        let (invoice, receive_op) = serde_json::from_value::<(Bolt11Invoice, OperationId)>(
            cmd!(
                client,
                "module",
                "lnv2",
                "receive",
                gw_cln.addr.clone(),
                "1000"
            )
            .out_json()
            .await?,
        )?;

        let send_op = serde_json::from_value::<OperationId>(
            cmd!(
                client,
                "module",
                "lnv2",
                "send",
                gw_lnd.addr.clone(),
                invoice.to_string()
            )
            .out_json()
            .await?,
        )?;

        assert_eq!(
            cmd!(
                client,
                "module",
                "lnv2",
                "await-send",
                serde_json::to_string(&send_op)?.substring(1, 65)
            )
            .out_json()
            .await?,
            serde_json::to_value(FinalSendState::Success).expect("JSON serialization failed"),
        );

        assert_eq!(
            cmd!(
                client,
                "module",
                "lnv2",
                "await-receive",
                serde_json::to_string(&receive_op)?.substring(1, 65)
            )
            .out_json()
            .await?,
            serde_json::to_value(FinalReceiveState::Claimed).expect("JSON serialization failed"),
        );

        Ok(())
    })
    .await
}
