#![deny(clippy::pedantic)]

use std::collections::BTreeMap;
use std::env;
use std::fs::remove_dir_all;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::ensure;
use clap::{Parser, Subcommand};
use devimint::envs::FM_DATA_DIR_ENV;
use devimint::federation::Federation;
use devimint::util::{ProcessManager, poll_with_timeout};
use devimint::version_constants::{VERSION_0_5_0_ALPHA, VERSION_0_6_0_ALPHA};
use devimint::{Gatewayd, LightningNode, cmd, util};
use fedimint_core::config::FederationId;
use fedimint_core::util::backoff_util::aggressive_backoff_long;
use fedimint_core::util::retry;
use fedimint_core::{Amount, BitcoinAmountOrAll};
use fedimint_gateway_common::{FederationInfo, GatewayBalances, GatewayFedConfig};
use fedimint_logging::LOG_TEST;
use fedimint_testing_core::node_type::LightningNodeType;
use itertools::Itertools;
use tracing::{debug, info, warn};

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
        #[arg(long)]
        old_gateway_cli_path: PathBuf,
        #[arg(long)]
        new_gateway_cli_path: PathBuf,
    },
    BackupRestoreTest,
    LiquidityTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest { gateway_type } => Box::pin(config_test(gateway_type)).await,
        GatewayTest::GatewaydMnemonic {
            old_gatewayd_path,
            new_gatewayd_path,
            old_gateway_cli_path,
            new_gateway_cli_path,
        } => {
            mnemonic_upgrade_test(
                old_gatewayd_path,
                new_gatewayd_path,
                old_gateway_cli_path,
                new_gateway_cli_path,
            )
            .await
        }
        GatewayTest::BackupRestoreTest => Box::pin(backup_restore_test()).await,
        GatewayTest::LiquidityTest => Box::pin(liquidity_test()).await,
    }
}

async fn backup_restore_test() -> anyhow::Result<()> {
    Box::pin(
        devimint::run_devfed_test().call(|dev_fed, process_mgr| async move {
            let gatewayd_version = util::Gatewayd::version_or_default().await;
            if gatewayd_version < *VERSION_0_5_0_ALPHA {
                warn!(target: LOG_TEST, "Gateway backup-restore is not supported below v0.5.0");
                return Ok(());
            }

            let gw = if devimint::util::supports_lnv2() {
                dev_fed.gw_ldk_connected().await?
            } else {
                dev_fed.gw_lnd_registered().await?
            };

            let fed = dev_fed.fed().await?;
            fed.pegin_gateways(10_000_000, vec![gw]).await?;

            let mnemonic = gw.get_mnemonic().await?.mnemonic;

            // Recover without a backup
            info!(target: LOG_TEST, "Wiping gateway and recovering without a backup...");
            let ln = gw.ln.clone();
            let new_gw = stop_and_recover_gateway(
                process_mgr.clone(),
                mnemonic.clone(),
                gw.to_owned(),
                ln.clone(),
                fed,
            )
            .await?;

            // Recover with a backup
            info!(target: LOG_TEST, "Wiping gateway and recovering with a backup...");
            info!(target: LOG_TEST, "Creating backup...");
            new_gw.backup_to_fed(fed).await?;
            stop_and_recover_gateway(process_mgr, mnemonic, new_gw, ln, fed).await?;

            info!(target: LOG_TEST, "backup_restore_test successful");
            Ok(())
        }),
    )
    .await
}

async fn stop_and_recover_gateway(
    process_mgr: ProcessManager,
    mnemonic: Vec<String>,
    old_gw: Gatewayd,
    new_ln: LightningNode,
    fed: &Federation,
) -> anyhow::Result<Gatewayd> {
    let gateway_balances =
        serde_json::from_value::<GatewayBalances>(cmd!(old_gw, "get-balances").out_json().await?)?;
    let before_onchain_balance = gateway_balances.onchain_balance_sats;

    // Stop the Gateway
    let gw_type = old_gw.ln.ln_type();
    let gw_name = old_gw.gw_name.clone();
    old_gw.terminate().await?;
    info!(target: LOG_TEST, "Terminated Gateway");

    // Delete the gateway's database
    let data_dir: PathBuf = env::var(FM_DATA_DIR_ENV)
        .expect("Data dir is not set")
        .parse()
        .expect("Could not parse data dir");
    let gw_db = data_dir.join(gw_name.clone()).join("gatewayd.db");
    remove_dir_all(gw_db)?;
    info!(target: LOG_TEST, "Deleted the Gateway's database");

    if gw_type == LightningNodeType::Ldk {
        // Delete LDK's database as well
        let ldk_data_dir = data_dir.join(gw_name).join("ldk_node");
        remove_dir_all(ldk_data_dir)?;
        info!(target: LOG_TEST, "Deleted LDK's database");
    }

    let seed = mnemonic.join(" ");
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("FM_GATEWAY_MNEMONIC", seed) };
    let new_gw = Gatewayd::new(&process_mgr, new_ln).await?;
    let new_mnemonic = new_gw.get_mnemonic().await?.mnemonic;
    assert_eq!(mnemonic, new_mnemonic);
    info!(target: LOG_TEST, "Verified mnemonic is the same after creating new Gateway");

    let federations = serde_json::from_value::<Vec<FederationInfo>>(
        new_gw.get_info().await?["federations"].clone(),
    )?;
    assert_eq!(0, federations.len());
    info!(target: LOG_TEST, "Verified new Gateway has no federations");

    new_gw.recover_fed(fed).await?;

    let gateway_balances =
        serde_json::from_value::<GatewayBalances>(cmd!(new_gw, "get-balances").out_json().await?)?;
    let ecash_balance = gateway_balances
        .ecash_balances
        .first()
        .expect("Should have one joined federation");
    assert_eq!(
        10_000_000,
        ecash_balance.ecash_balance_msats.sats_round_down()
    );
    let after_onchain_balance = gateway_balances.onchain_balance_sats;
    assert_eq!(before_onchain_balance, after_onchain_balance);
    info!(target: LOG_TEST, "Verified balances after recovery");

    Ok(new_gw)
}

/// TODO(v0.5.0): We do not need to run the `gatewayd-mnemonic` test from v0.4.0
/// -> v0.5.0 over and over again. Once we have verified this test passes for
/// v0.5.0, it can safely be removed.
async fn mnemonic_upgrade_test(
    old_gatewayd_path: PathBuf,
    new_gatewayd_path: PathBuf,
    old_gateway_cli_path: PathBuf,
    new_gateway_cli_path: PathBuf,
) -> anyhow::Result<()> {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", old_gatewayd_path) };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("FM_GATEWAY_CLI_BASE_EXECUTABLE", old_gateway_cli_path) };
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("FM_ENABLE_MODULE_LNV2", "0") };

    devimint::run_devfed_test()
        .call(|dev_fed, process_mgr| async move {
            let gatewayd_version = util::Gatewayd::version_or_default().await;
            let gateway_cli_version = util::GatewayCli::version_or_default().await;
            info!(
                target: LOG_TEST,
                gatewayd_version = %gatewayd_version,
                gateway_cli_version = %gateway_cli_version,
                "Running gatewayd mnemonic test"
            );

            let mut gw_lnd = dev_fed.gw_lnd_registered().await?.to_owned();
            let fed = dev_fed.fed().await?;
            let federation_id = FederationId::from_str(fed.calculate_federation_id().as_str())?;

            gw_lnd
                .restart_with_bin(&process_mgr, &new_gatewayd_path, &new_gateway_cli_path)
                .await?;

            // Gateway mnemonic is only support in >= v0.5.0
            let new_gatewayd_version = util::Gatewayd::version_or_default().await;
            if new_gatewayd_version < *VERSION_0_5_0_ALPHA {
                warn!(target: LOG_TEST, "Gateway mnemonic test is not supported below v0.5.0");
                return Ok(());
            }

            // Verify that we have a legacy federation
            let mnemonic_response = gw_lnd.get_mnemonic().await?;
            assert!(
                mnemonic_response
                    .legacy_federations
                    .contains(&federation_id)
            );

            info!(target: LOG_TEST, "Verified a legacy federation exists");

            // Leave federation
            gw_lnd.leave_federation(federation_id).await?;

            // Rejoin federation
            gw_lnd.connect_fed(fed).await?;

            // Verify that the legacy federation is recognized
            let mnemonic_response = gw_lnd.get_mnemonic().await?;
            assert!(
                mnemonic_response
                    .legacy_federations
                    .contains(&federation_id)
            );
            assert_eq!(mnemonic_response.legacy_federations.len(), 1);

            info!(target: LOG_TEST, "Verified leaving and re-joining preservers legacy federation");

            // Leave federation and delete database to force migration to mnemonic
            gw_lnd.leave_federation(federation_id).await?;

            let data_dir: PathBuf = env::var(FM_DATA_DIR_ENV)
                .expect("Data dir is not set")
                .parse()
                .expect("Could not parse data dir");
            let gw_fed_db = data_dir
                .join(gw_lnd.gw_name.clone())
                .join(format!("{federation_id}.db"));
            remove_dir_all(gw_fed_db)?;

            gw_lnd.connect_fed(fed).await?;

            // Verify that the re-connected federation is not a legacy federation
            let mnemonic_response = gw_lnd.get_mnemonic().await?;
            assert!(
                !mnemonic_response
                    .legacy_federations
                    .contains(&federation_id)
            );
            assert_eq!(mnemonic_response.legacy_federations.len(), 0);

            info!(target: LOG_TEST, "Verified deleting database will migrate the federation to use mnemonic");

            info!(target: LOG_TEST, "Successfully completed mnemonic upgrade test");

            Ok(())
        })
        .await
}

/// Test that sets and verifies configurations within the gateway
#[allow(clippy::too_many_lines)]
async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    Box::pin(
        devimint::run_devfed_test()
            .num_feds(2)
            .call(|dev_fed, process_mgr| async move {
                let gatewayd_version = util::Gatewayd::version_or_default().await;
                if gatewayd_version < *VERSION_0_5_0_ALPHA && gw_type == LightningNodeType::Ldk {
                    return Ok(());
                }

                let gw = match gw_type {
                    LightningNodeType::Lnd => dev_fed.gw_lnd_registered().await?,
                    LightningNodeType::Ldk => dev_fed.gw_ldk_connected().await?,
                };

                // Try to connect to already connected federation
                let invite_code = dev_fed.fed().await?.invite_code()?;
                let output = cmd!(gw, "connect-fed", invite_code.clone())
                    .out_json()
                    .await;
                assert!(
                    output.is_err(),
                    "Connecting to the same federation succeeded"
                );
                info!(target: LOG_TEST, "Verified that gateway couldn't connect to already connected federation");

                let gatewayd_version = util::Gatewayd::version_or_default().await;

                // Change the routing fees for a specific federation
                let fed_id = dev_fed.fed().await?.calculate_federation_id();
                gw.set_federation_routing_fee(fed_id.clone(), 20, 20000)
                    .await?;

                let lightning_fee = gw.get_lightning_fee(fed_id.clone()).await?;
                assert_eq!(
                    lightning_fee.base.msats, 20,
                    "Federation base msat is not 20"
                );
                assert_eq!(
                    lightning_fee.parts_per_million, 20000,
                    "Federation proportional millionths is not 20000"
                );
                info!(target: LOG_TEST, "Verified per-federation routing fees changed");

                let info_value = cmd!(gw, "info").out_json().await?;
                let federations = info_value["federations"]
                    .as_array()
                    .expect("federations is an array");
                assert_eq!(
                    federations.len(),
                    1,
                    "Gateway did not have one connected federation"
                );

                // TODO(support:v0.4): a bug calling `gateway-cli config` was fixed in v0.5.0
                // see: https://github.com/fedimint/fedimint/pull/5803
                if gatewayd_version >= *VERSION_0_5_0_ALPHA
                    && gatewayd_version < *VERSION_0_6_0_ALPHA
                {
                    // Get the federation's config and verify it parses correctly
                    let config_val = cmd!(gw, "config", "--federation-id", fed_id)
                        .out_json()
                        .await?;
                    serde_json::from_value::<GatewayFedConfig>(config_val)?;
                } else if gatewayd_version >= *VERSION_0_6_0_ALPHA {
                    // Get the federation's config and verify it parses correctly
                    let config_val = cmd!(gw, "cfg", "client-config", "--federation-id", fed_id)
                        .out_json()
                        .await?;
                    serde_json::from_value::<GatewayFedConfig>(config_val)?;
                }

                // Spawn new federation
                let bitcoind = dev_fed.bitcoind().await?;
                let new_fed = Federation::new(
                    &process_mgr,
                    bitcoind.clone(),
                    false,
                    1,
                    "config-test".to_string(),
                )
                .await?;
                let new_fed_id = new_fed.calculate_federation_id();
                info!(target: LOG_TEST, "Successfully spawned new federation");

                let new_invite_code = new_fed.invite_code()?;
                cmd!(gw, "connect-fed", new_invite_code.clone())
                    .out_json()
                    .await?;

                let (default_base, default_ppm) = if gatewayd_version >= *VERSION_0_6_0_ALPHA {
                    (50000, 5000)
                } else {
                    (0, 10000)
                };

                let lightning_fee = gw.get_lightning_fee(new_fed_id.clone()).await?;
                assert_eq!(
                    lightning_fee.base.msats, default_base,
                    "Default Base msat for new federation was not correct"
                );
                assert_eq!(
                    lightning_fee.parts_per_million, default_ppm,
                    "Default Base msat for new federation was not correct"
                );

                info!(target: LOG_TEST, federation_id = %new_fed_id, "Verified new federation");

                // Peg-in sats to gw for the new fed
                let pegin_amount = Amount::from_msats(10_000_000);
                new_fed
                    .pegin_gateways(pegin_amount.sats_round_down(), vec![gw])
                    .await?;

                // Verify `info` returns multiple federations
                let info_value = cmd!(gw, "info").out_json().await?;
                let federations = info_value["federations"]
                    .as_array()
                    .expect("federations is an array");

                assert_eq!(
                    federations.len(),
                    2,
                    "Gateway did not have two connected federations"
                );

                let federation_fake_scids =
                    serde_json::from_value::<Option<BTreeMap<u64, FederationId>>>(
                        info_value
                            .get("channels")
                            .or_else(|| info_value.get("federation_fake_scids"))
                            .expect("field  exists")
                            .to_owned(),
                    )
                    .expect("cannot parse")
                    .expect("should have scids");

                assert_eq!(
                    federation_fake_scids.keys().copied().collect::<Vec<u64>>(),
                    vec![1, 2]
                );

                let first_fed_info = federations
                    .iter()
                    .find(|i| {
                        *i["federation_id"]
                            .as_str()
                            .expect("should parse as str")
                            .to_string()
                            == fed_id
                    })
                    .expect("Could not find federation");

                let second_fed_info = federations
                    .iter()
                    .find(|i| {
                        *i["federation_id"]
                            .as_str()
                            .expect("should parse as str")
                            .to_string()
                            == new_fed_id
                    })
                    .expect("Could not find federation");

                let first_fed_balance_msat =
                    serde_json::from_value::<Amount>(first_fed_info["balance_msat"].clone())
                        .expect("fed should have balance");

                let second_fed_balance_msat =
                    serde_json::from_value::<Amount>(second_fed_info["balance_msat"].clone())
                        .expect("fed should have balance");

                assert_eq!(first_fed_balance_msat, Amount::ZERO);
                assert_eq!(second_fed_balance_msat, pegin_amount);

                leave_federation(gw, fed_id, 1).await?;
                leave_federation(gw, new_fed_id, 2).await?;

                // Rejoin new federation, verify that the balance is the same
                let output = cmd!(gw, "connect-fed", new_invite_code.clone())
                    .out_json()
                    .await?;
                let rejoined_federation_balance_msat =
                    serde_json::from_value::<Amount>(output["balance_msat"].clone())
                        .expect("fed has balance");

                assert_eq!(second_fed_balance_msat, rejoined_federation_balance_msat);

                info!(target: LOG_TEST, "Gateway configuration test successful");
                Ok(())
            }),
    )
    .await
}

/// Test that verifies the various liquidity tools (onchain, lightning, ecash)
/// work correctly.
#[allow(clippy::too_many_lines)]
async fn liquidity_test() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let federation = dev_fed.fed().await?;

            if !devimint::util::supports_lnv2() {
                info!(target: LOG_TEST, "LNv2 is not supported, which is necessary for LDK GW and liquidity test");
                return Ok(());
            }

            let gw_lnd = dev_fed.gw_lnd_registered().await?;
            let gw_ldk = dev_fed.gw_ldk_connected().await?;
            let gw_ldk_second = dev_fed.gw_ldk_second_connected().await?;
            let gateways = [gw_lnd, gw_ldk].to_vec();

            let gateway_matrix = gateways
                .iter()
                .cartesian_product(gateways.iter())
                .filter(|(a, b)| a.ln.ln_type() != b.ln.ln_type());

            info!(target: LOG_TEST, "Pegging-in gateways...");
            federation
                .pegin_gateways(1_000_000, gateways.clone())
                .await?;

            info!(target: LOG_TEST, "Testing ecash payments between gateways...");
            for (gw_send, gw_receive) in gateway_matrix.clone() {
                info!(
                    target: LOG_TEST,
                    gw_send = %gw_send.ln.ln_type(),
                    gw_receive = %gw_receive.ln.ln_type(),
                    "Testing ecash payment",
                );

                let fed_id = federation.calculate_federation_id();
                let prev_send_ecash_balance = gw_send.ecash_balance(fed_id.clone()).await?;
                let prev_receive_ecash_balance = gw_receive.ecash_balance(fed_id.clone()).await?;
                let ecash = gw_send.send_ecash(fed_id.clone(), 500_000).await?;
                gw_receive.receive_ecash(ecash).await?;
                let after_send_ecash_balance = gw_send.ecash_balance(fed_id.clone()).await?;
                let after_receive_ecash_balance = gw_receive.ecash_balance(fed_id.clone()).await?;
                assert_eq!(prev_send_ecash_balance - 500_000, after_send_ecash_balance);
                assert_eq!(
                    prev_receive_ecash_balance + 500_000,
                    after_receive_ecash_balance
                );
            }

            info!(target: LOG_TEST, "Testing payments between gateways...");

            for (gw_send, gw_receive) in gateway_matrix.clone() {
                info!(
                    target: LOG_TEST,
                    gw_send = %gw_send.ln.ln_type(),
                    gw_receive = %gw_receive.ln.ln_type(),
                    "Testing lightning payment",
                );

                let invoice = gw_receive.create_invoice(1_000_000).await?;
                gw_send.pay_invoice(invoice).await?;
            }

            info!(target: LOG_TEST, "Testing paying through LND Gateway...");
            // Need to try to pay the invoice multiple times in case the channel graph has
            // not been updated yet. LDK's channel graph updates slowly in these
            // tests, so we need to try for awhile.
            poll_with_timeout("LDK2 pay LDK", Duration::from_secs(180), || async {
                debug!(target: LOG_TEST, "Trying LDK2 -> LND -> LDK...");
                let invoice = gw_ldk
                    .create_invoice(1_550_000)
                    .await
                    .map_err(ControlFlow::Continue)?;
                gw_ldk_second
                    .pay_invoice(invoice.clone())
                    .await
                    .map_err(ControlFlow::Continue)?;
                Ok(())
            })
            .await?;

            info!(target: LOG_TEST, "Pegging-out gateways...");
            federation
                .pegout_gateways(500_000_000, gateways.clone())
                .await?;

            info!(target: LOG_TEST, "Testing closing all channels...");
            gw_ldk_second.close_all_channels().await?;
            gw_ldk.close_all_channels().await?;
            let bitcoind = dev_fed.bitcoind().await?;
            // Need to mine enough blocks in case the channels are force closed.
            bitcoind.mine_blocks(2016).await?;
            let block_height = bitcoind.get_block_count().await? - 1;
            gw_ldk_second.wait_for_block_height(block_height).await?;
            check_empty_lightning_balance(gw_ldk_second).await?;
            gw_ldk.wait_for_block_height(block_height).await?;
            check_empty_lightning_balance(gw_ldk).await?;
            check_empty_lightning_balance(gw_lnd).await?;

            info!(target: LOG_TEST, "Testing sending onchain...");
            // TODO: LND is sometimes keeping 10000 sats as reserve when sending onchain
            // For now we will skip checking LND.
            gw_ldk
                .send_onchain(dev_fed.bitcoind().await?, BitcoinAmountOrAll::All, 10)
                .await?;
            gw_ldk_second
                .send_onchain(dev_fed.bitcoind().await?, BitcoinAmountOrAll::All, 10)
                .await?;
            check_empty_onchain_balance(gw_ldk).await?;
            check_empty_onchain_balance(gw_ldk_second).await?;

            Ok(())
        })
        .await
}

async fn check_empty_onchain_balance(gw: &Gatewayd) -> anyhow::Result<()> {
    retry(
        "Wait for onchain balance update",
        aggressive_backoff_long(),
        || async {
            let curr_balance = gw.get_balances().await?.onchain_balance_sats;
            let gw_name = gw.gw_name.clone();
            ensure!(
                curr_balance == 0,
                "Gateway onchain balance is not empty: {curr_balance} gw_name: {gw_name}"
            );
            Ok(())
        },
    )
    .await
}

async fn check_empty_lightning_balance(gw: &Gatewayd) -> anyhow::Result<()> {
    let balances = gw.get_balances().await?;
    let curr_lightning_balance = balances.lightning_balance_msats;
    ensure!(
        curr_lightning_balance == 0,
        "Close channels did not sweep all lightning funds"
    );
    let inbound_lightning_balance = balances.inbound_lightning_liquidity_msats;
    ensure!(
        inbound_lightning_balance == 0,
        "Close channels did not sweep all lightning funds"
    );
    Ok(())
}

/// Leaves the specified federation by issuing a `leave-fed` POST request to the
/// gateway.
async fn leave_federation(gw: &Gatewayd, fed_id: String, expected_scid: u64) -> anyhow::Result<()> {
    let gatewayd_version = util::Gatewayd::version_or_default().await;
    let leave_fed = cmd!(gw, "leave-fed", "--federation-id", fed_id.clone())
        .out_json()
        .await
        .expect("Leaving the federation failed");

    let federation_id: FederationId = serde_json::from_value(leave_fed["federation_id"].clone())?;
    assert_eq!(federation_id.to_string(), fed_id);

    // TODO(support:v0.4): `federation_index` was introduced in v0.5.0
    // see: https://github.com/fedimint/fedimint/pull/5971
    let scid = if gatewayd_version < *VERSION_0_5_0_ALPHA {
        let channel_id: Option<u64> = serde_json::from_value(leave_fed["channel_id"].clone())?;
        channel_id.expect("must have channel id")
    } else if gatewayd_version >= *VERSION_0_5_0_ALPHA && gatewayd_version < *VERSION_0_6_0_ALPHA {
        serde_json::from_value::<u64>(leave_fed["federation_index"].clone())?
    } else {
        serde_json::from_value::<u64>(leave_fed["config"]["federation_index"].clone())?
    };

    assert_eq!(scid, expected_scid);

    info!(target: LOG_TEST, federation_id = %fed_id, "Verified gateway left federation");
    Ok(())
}
