#![warn(clippy::pedantic)]

use clap::{Parser, Subcommand};
use devimint::version_constants::VERSION_0_3_0;
use devimint::{cmd, util};
use fedimint_testing::gateway::LightningNodeType;
use ln_gateway::rpc::{FederationInfo, GatewayInfo};
use tracing::info;

#[derive(Parser)]
struct GatewayTestOpts {
    #[clap(subcommand)]
    test: GatewayTest,

    #[arg(long = "gw-type")]
    gateway_type: LightningNodeType,
}

#[derive(Debug, Clone, Subcommand)]
enum GatewayTest {
    ConfigTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest => config_test(opts.gateway_type).await,
    }
}

async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed| async move {
        let gw = match gw_type {
            LightningNodeType::Lnd => dev_fed.gw_lnd_registered().await?,
            LightningNodeType::Cln => dev_fed.gw_cln_registered().await?,
        };

        // Try to connect to already connected federation
        let gatewayd_version = util::Gatewayd::version_or_default().await;
        if gatewayd_version >= *VERSION_0_3_0 {
            let invite_code = dev_fed.fed().await?.invite_code()?;
            let output = cmd!(gw, "connect-fed", invite_code.clone())
                .out_json()
                .await;
            assert!(
                output.is_err(),
                "Connecting to the same federation succeeded"
            );
            info!("Verified that gateway couldn't connect to already connected federation");
        }

        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        if fedimint_cli_version >= *VERSION_0_3_0 && gatewayd_version >= *VERSION_0_3_0 {
            // Change the default routing fees
            let new_default_routing_fees = "10,10000";
            cmd!(
                gw,
                "set-configuration",
                "--routing-fees",
                new_default_routing_fees
            )
            .run()
            .await?;
            info!(?new_default_routing_fees, "Changed gateway routing fees");

            let info_value = cmd!(gw, "info").out_json().await?;
            let gateway_info: GatewayInfo =
                serde_json::from_value(info_value).expect("Could not parse GatewayInfo");
            assert!(gateway_info.fees.is_some(), "Fees must be set");
            assert_eq!(
                gateway_info.fees.unwrap().base_msat,
                10,
                "Default Base msat is not 10"
            );
            assert_eq!(
                gateway_info.fees.unwrap().proportional_millionths,
                10000,
                "Default proportional millionths is not 10000"
            );
            info!("Verified default routing fees changed");

            // Change the routing fees for a specific federation
            let fed_id = dev_fed.fed().await?.calculate_federation_id();
            let new_fed_routing_fees = format!("{},20,20000", fed_id.clone());
            cmd!(
                gw,
                "set-configuration",
                "--per-federation-routing-fees",
                new_fed_routing_fees
            )
            .run()
            .await?;

            let info_value = cmd!(gw, "info").out_json().await?;
            let gateway_info: GatewayInfo =
                serde_json::from_value(info_value).expect("Could not parse GatewayInfo");
            let federation_fees = gateway_info
                .federations
                .first()
                .expect("Must have a connected federation")
                .routing_fees
                .as_ref()
                .expect("Federation routing fees should be set");
            assert_eq!(
                federation_fees.base_msat, 20,
                "Federation base msat is not 20"
            );
            assert_eq!(
                federation_fees.proportional_millionths, 20000,
                "Federation proportional millionths is not 20000"
            );
            info!("Verified per-federation routing fees changed");

            // `leave-fed` did not return any output until 0.3.0
            let leave_fed = cmd!(gw, "leave-fed", "--federation-id", fed_id.clone())
                .out_json()
                .await
                .expect("Leaving the federation failed");

            let fed_info: FederationInfo =
                serde_json::from_value(leave_fed).expect("Could not parse FederationInfo");
            assert_eq!(fed_info.federation_id.to_string(), fed_id);
            info!("Verified gateway left federation {fed_id}");
        }

        info!("Gateway configuration test successful");
        Ok(())
    })
    .await
}
