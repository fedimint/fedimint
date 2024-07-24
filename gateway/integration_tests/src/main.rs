#![warn(clippy::pedantic)]

use clap::{Parser, Subcommand};
use devimint::federation::Federation;
use devimint::version_constants::{VERSION_0_3_0, VERSION_0_4_0_ALPHA};
use devimint::{cmd, util, Gatewayd};
use fedimint_core::Amount;
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
        GatewayTest::ConfigTest => Box::pin(config_test(opts.gateway_type)).await,
    }
}

/// Test that sets and verifies configurations within the gateway
#[allow(clippy::too_many_lines)]
async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    Box::pin(devimint::run_devfed_test(
        |dev_fed, process_mgr| async move {
            let gatewayd_version = util::Gatewayd::version_or_default().await;
            if gatewayd_version < *VERSION_0_4_0_ALPHA && gw_type == LightningNodeType::Ldk {
                return Ok(());
            }

            let gw = match gw_type {
                LightningNodeType::Lnd => dev_fed.gw_lnd_registered().await?,
                LightningNodeType::Cln => dev_fed.gw_cln_registered().await?,
                LightningNodeType::Ldk => dev_fed
                    .gw_ldk_registered()
                    .await?
                    .as_ref()
                    .expect("LDK Gateway should be available"),
            };

            let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
            let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
            if fedimint_cli_version < *VERSION_0_3_0 || gatewayd_version < *VERSION_0_3_0 {
                info!("fedmint-cli version that didn't support unknown modules");
                return Ok(());
            }

            // Try to connect to already connected federation
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

                let gateway_info = get_gateway_info(gw).await?;
                assert_eq!(
                    gateway_info.federations.len(),
                    1,
                    "Gateway did not have one connected federation"
                );
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

                // Change password for gateway
                gw.change_password("theresnosecondbest", "newpassword")
                    .run()
                    .await?;
                get_gateway_info(gw)
                    .await
                    .expect_err("Expected info to return error since the password has changed");
                gw.change_password("newpassword", "theresnosecondbest")
                    .run()
                    .await?;
                cmd!(gw, "set-configuration", "--network", "regtest")
                    .run()
                    .await
                    .expect_err("Cannot change the network while connected to a federation");
                info!("Verified password change and network cannot be changed.");

                // Spawn new federation
                let bitcoind = dev_fed.bitcoind().await?;
                let new_fed = Federation::new(
                    &process_mgr,
                    bitcoind.clone(),
                    4,
                    false,
                    "config-test".to_string(),
                )
                .await?;
                let new_fed_id = new_fed.calculate_federation_id();
                info!("Successfully spawned new federation");

                let new_invite_code = new_fed.invite_code()?;
                let output = cmd!(gw, "connect-fed", new_invite_code.clone())
                    .out_json()
                    .await?;
                let federation_info: FederationInfo =
                    serde_json::from_value(output).expect("Could not parse FederationInfo");
                // New federation should have the default fees
                let fees = federation_info
                    .routing_fees
                    .expect("Routing fees were none");
                assert_eq!(
                    fees.base_msat, 10,
                    "Default Base msat for new federation was not correct"
                );
                assert_eq!(
                    fees.proportional_millionths, 10000,
                    "Default Base msat for new federation was not correct"
                );
                info!(?new_fed_id, "Verified new federation");

                // Peg-in sats to gw for the new fed
                let pegin_amount = Amount::from_msats(10_000_000);
                new_fed
                    .pegin_gateway(pegin_amount.sats_round_down(), gw)
                    .await?;

                // Verify `info` returns multiple federations
                let gateway_info = get_gateway_info(gw).await?;
                assert_eq!(
                    gateway_info.federations.len(),
                    2,
                    "Gateway did not have two connected federations"
                );
                assert_eq!(
                    gateway_info
                        .channels
                        .unwrap()
                        .keys()
                        .copied()
                        .collect::<Vec<u64>>(),
                    vec![1, 2]
                );

                let first_fed_info = gateway_info
                    .federations
                    .iter()
                    .find(|i| i.federation_id.to_string() == fed_id)
                    .expect("Could not find federation");
                let second_fed_info = gateway_info
                    .federations
                    .iter()
                    .find(|i| i.federation_id.to_string() == new_fed_id)
                    .expect("Could not find federation");
                assert_eq!(first_fed_info.balance_msat, Amount::ZERO);
                assert_eq!(second_fed_info.balance_msat, pegin_amount);

                leave_federation(gw, fed_id, 1).await?;
                leave_federation(gw, new_fed_id, 2).await?;
            }

            info!("Gateway configuration test successful");
            Ok(())
        },
    ))
    .await
}

/// Retrieves the `GatewayInfo` by issuing an `info` GET request to the gateway.
async fn get_gateway_info(gw: &Gatewayd) -> anyhow::Result<GatewayInfo> {
    let info_value = cmd!(gw, "info").out_json().await?;
    Ok(serde_json::from_value::<GatewayInfo>(info_value).expect("Could not parse GatewayInfo"))
}

/// Leaves the specified federation by issuing a `leave-fed` POST request to the
/// gateway.
async fn leave_federation(
    gw: &Gatewayd,
    fed_id: String,
    expected_scid: u64,
) -> anyhow::Result<FederationInfo> {
    let leave_fed = cmd!(gw, "leave-fed", "--federation-id", fed_id.clone())
        .out_json()
        .await
        .expect("Leaving the federation failed");

    let fed_info: FederationInfo =
        serde_json::from_value(leave_fed).expect("Could not parse FederationInfo");
    assert_eq!(fed_info.federation_id.to_string(), fed_id);
    assert_eq!(fed_info.channel_id, Some(expected_scid));
    info!("Verified gateway left federation {fed_id}");
    Ok(fed_info)
}
