use clap::Parser;
use devimint::version_constants::VERSION_0_4_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::core::OperationId;
use fedimint_lnv2_client::ReceiveState;
use fedimint_testing::gateway::LightningNodeType;
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::info;

#[derive(Parser)]
struct LightningTestOpts {
    #[arg(long = "gw-type")]
    gateway_type: LightningNodeType,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = LightningTestOpts::parse();
    lightning_test(opts.gateway_type).await
}

async fn lightning_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _| async move {
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

        let gw = match gw_type {
            LightningNodeType::Lnd => dev_fed.gw_lnd_registered().await?,
            LightningNodeType::Cln => dev_fed.gw_cln_registered().await?,
        };
        fed.pegin_gateway(100_0000, gw).await?;

        let client = fed.new_joined_client("lnv2-module-client").await?;

        let value = cmd!(
            client,
            "module",
            "lnv2",
            "receive",
            gw.addr.clone(),
            "10000"
        )
        .out_json()
        .await?;
        let (invoice, receive_op) = serde_json::from_value::<(Bolt11Invoice, OperationId)>(value)?;
        match gw_type {
            LightningNodeType::Cln => {
                let lnd = dev_fed.lnd().await?;
                lnd.pay_bolt11_invoice(invoice.to_string()).await?;
                info!("LND successfully paid LNv2 invoice via CLN gateway");
            }
            LightningNodeType::Lnd => {
                let cln = dev_fed.cln().await?;
                cln.pay_bolt11_invoice(invoice.to_string()).await?;
                info!("CLN successfully paid LNv2 invoice via LND gateway");
            }
        }

        assert_eq!(
            cmd!(
                client,
                "module",
                "lnv2",
                "await-receive",
                serde_json::to_string(&receive_op)?.substring(1, 65),
            )
            .out_json()
            .await?,
            serde_json::to_value(ReceiveState::Claimed).expect("JSON serialization failed"),
        );

        info!("Client successfully claimed incoming LNv2 payment");

        Ok(())
    })
    .await
}
