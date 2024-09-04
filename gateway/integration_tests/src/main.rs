#![deny(clippy::pedantic)]

use std::env;
use std::fs::remove_dir_all;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use devimint::envs::FM_DATA_DIR_ENV;
use devimint::federation::Federation;
use devimint::version_constants::{VERSION_0_3_0, VERSION_0_5_0_ALPHA};
use devimint::{cmd, util, Gatewayd};
use fedimint_core::config::FederationId;
use fedimint_core::Amount;
use fedimint_testing::gateway::LightningNodeType;
use ln_gateway::rpc::{FederationInfo, GatewayFedConfig, GatewayInfo};
use tracing::info;

#[derive(Parser)]
struct GatewayTestOpts {
    #[clap(subcommand)]
    test: GatewayTest,
}

#[derive(Debug, Clone, Subcommand)]
enum GatewayTest {
    ConfigTest {
        #[arg(long = "gw-type")]
        gateway_type: LightningNodeType,
    },
    GatewaydMnemonic {
        #[arg(long)]
        old_gatewayd_path: PathBuf,
        #[arg(long)]
        new_gatewayd_path: PathBuf,
        #[arg(long = "gw-type")]
        gateway_type: LightningNodeType,
        #[arg(long)]
        old_gateway_cli_path: PathBuf,
        #[arg(long)]
        new_gateway_cli_path: PathBuf,
        #[arg(long)]
        old_gateway_cln_extension_path: PathBuf,
        #[arg(long)]
        new_gateway_cln_extension_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest { gateway_type } => Box::pin(config_test(gateway_type)).await,
        GatewayTest::GatewaydMnemonic {
            old_gatewayd_path,
            new_gatewayd_path,
            gateway_type,
            old_gateway_cli_path,
            new_gateway_cli_path,
            old_gateway_cln_extension_path,
            new_gateway_cln_extension_path,
        } => {
            mnemonic_upgrade_test(
                old_gatewayd_path,
                new_gatewayd_path,
                gateway_type,
                old_gateway_cli_path,
                new_gateway_cli_path,
                old_gateway_cln_extension_path,
                new_gateway_cln_extension_path,
            )
            .await
        }
    }
}

/// TODO(v0.5.0): We do not need to run the `gatewayd-mnemonic` test from v0.4.0
/// -> v0.5.0 over and over again. Once we have verified this test passes for
/// v0.5.0, it can safely be removed.
async fn mnemonic_upgrade_test(
    old_gatewayd_path: PathBuf,
    new_gatewayd_path: PathBuf,
    gw_type: LightningNodeType,
    old_gateway_cli_path: PathBuf,
    new_gateway_cli_path: PathBuf,
    old_gateway_cln_extension_path: PathBuf,
    new_gateway_cln_extension_path: PathBuf,
) -> anyhow::Result<()> {
    std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", old_gatewayd_path);
    std::env::set_var("FM_GATEWAY_CLI_BASE_EXECUTABLE", old_gateway_cli_path);
    std::env::set_var(
        "FM_GATEWAY_CLN_EXTENSION_BASE_EXECUTABLE",
        old_gateway_cln_extension_path,
    );

    devimint::run_devfed_test(|dev_fed, process_mgr| async move {
        let gatewayd_version = util::Gatewayd::version_or_default().await;
        let gateway_cli_version = util::GatewayCli::version_or_default().await;
        info!(
            ?gatewayd_version,
            ?gateway_cli_version,
            "Running gatewayd mnemonic test"
        );

        let mut gw_lnd = dev_fed.gw_lnd_registered().await?.to_owned();
        let fed = dev_fed.fed().await?;
        let federation_id = FederationId::from_str(fed.calculate_federation_id().as_str())?;
        let bitcoind = dev_fed.bitcoind().await?;

        gw_lnd
            .restart_with_bin(
                &process_mgr,
                &new_gatewayd_path,
                &new_gateway_cli_path,
                &new_gateway_cln_extension_path,
                bitcoind.clone(),
            )
            .await?;

        // Gateway mnemonic is only support in >= v0.5.0
        let new_gatewayd_version = util::Gatewayd::version_or_default().await;
        if new_gatewayd_version < *VERSION_0_5_0_ALPHA {
            info!("Gateway mnemonic test is not supported below v0.5.0");
            return Ok(());
        }

        // Verify that we have a legacy federation
        let mnemonic_response = gw_lnd.get_mnemonic().await?;
        assert!(mnemonic_response
            .legacy_federations
            .contains(&federation_id));

        info!("Verified a legacy federation exists");

        // Leave federation
        gw_lnd.leave_federation(federation_id).await?;

        // Rejoin federation
        gw_lnd.connect_fed(fed).await?;

        // Verify that the legacy federation is recognized
        let mnemonic_response = gw_lnd.get_mnemonic().await?;
        assert!(mnemonic_response
            .legacy_federations
            .contains(&federation_id));
        assert_eq!(mnemonic_response.legacy_federations.len(), 1);

        info!("Verified leaving and re-joining preservers legacy federation");

        // Leave federation and delete database to force migration to mnemonic
        gw_lnd.leave_federation(federation_id).await?;

        let data_dir: PathBuf = env::var(FM_DATA_DIR_ENV)
            .expect("Data dir is not set")
            .parse()
            .expect("Could not parse data dir");
        let gw_fed_db = data_dir
            .join(gw_type.to_string())
            .join(format!("{federation_id}.db"));
        remove_dir_all(gw_fed_db)?;

        gw_lnd.connect_fed(fed).await?;

        // Verify that the re-connected federation is not a legacy federation
        let mnemonic_response = gw_lnd.get_mnemonic().await?;
        assert!(!mnemonic_response
            .legacy_federations
            .contains(&federation_id));
        assert_eq!(mnemonic_response.legacy_federations.len(), 0);

        info!("Verified deleting database will migrate the federation to use mnemonic");

        // Restart CLN gateway but with a given mnemonic
        let mnemonic =
            "cereal fortune course waste wagon jaguar shoulder client modify view panic describe";
        std::env::set_var("FM_GATEWAY_MNEMONIC", mnemonic);
        let mut gw_cln = dev_fed.gw_cln_registered().await?.to_owned();
        gw_cln
            .restart_with_bin(
                &process_mgr,
                &new_gatewayd_path,
                &new_gateway_cli_path,
                &new_gateway_cln_extension_path,
                bitcoind.clone(),
            )
            .await?;
        let mnemonic_response = gw_cln.get_mnemonic().await?;
        assert!(mnemonic_response
            .legacy_federations
            .contains(&federation_id));
        assert_eq!(
            mnemonic_response.mnemonic,
            mnemonic
                .split_whitespace()
                .map(std::string::ToString::to_string)
                .collect::<Vec<String>>()
        );

        info!("Successfully completed mnemonic upgrade test");

        Ok(())
    })
    .await
}

/// Test that sets and verifies configurations within the gateway
#[allow(clippy::too_many_lines)]
async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    Box::pin(devimint::run_devfed_test(
        |dev_fed, process_mgr| async move {
            let gatewayd_version = util::Gatewayd::version_or_default().await;
            if gatewayd_version < *VERSION_0_5_0_ALPHA && gw_type == LightningNodeType::Ldk {
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

                // Get the federation's config and verify it parses correctly
                let config_val = cmd!(gw, "config", "--federation-id", fed_id)
                    .out_json()
                    .await?;
                serde_json::from_value::<GatewayFedConfig>(config_val)?;

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
                        .federation_fake_scids
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
    assert_eq!(fed_info.channel_id, expected_scid);
    info!("Verified gateway left federation {fed_id}");
    Ok(fed_info)
}
