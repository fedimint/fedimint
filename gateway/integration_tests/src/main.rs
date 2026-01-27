#![deny(clippy::pedantic)]

use std::collections::BTreeMap;
use std::fs::{remove_dir_all, remove_file};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::{env, ffi};

use clap::{Parser, Subcommand};
use devimint::cli::cleanup_on_exit;
use devimint::envs::FM_DATA_DIR_ENV;
use devimint::external::{Bitcoind, Esplora};
use devimint::federation::Federation;
use devimint::util::{ProcessManager, almost_equal, poll, poll_with_timeout};
use devimint::version_constants::{VERSION_0_8_2, VERSION_0_10_0_ALPHA};
use devimint::{Gatewayd, LightningNode, cli, cmd, util};
use fedimint_core::config::FederationId;
use fedimint_core::time::now;
use fedimint_core::{Amount, BitcoinAmountOrAll, bitcoin, default_esplora_server};
use fedimint_gateway_common::{
    FederationInfo, GatewayBalances, GatewayFedConfig, PaymentDetails, PaymentKind, PaymentStatus,
};
use fedimint_logging::LOG_TEST;
use fedimint_testing_core::node_type::LightningNodeType;
use itertools::Itertools;
use tracing::info;

#[derive(Parser)]
struct GatewayTestOpts {
    #[clap(subcommand)]
    test: GatewayTest,
}

#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::enum_variant_names)]
enum GatewayTest {
    ConfigTest {
        #[arg(long = "gw-type")]
        gateway_type: LightningNodeType,
    },
    BackupRestoreTest,
    LiquidityTest,
    EsploraTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest { gateway_type } => Box::pin(config_test(gateway_type)).await,
        GatewayTest::BackupRestoreTest => Box::pin(backup_restore_test()).await,
        GatewayTest::LiquidityTest => Box::pin(liquidity_test()).await,
        GatewayTest::EsploraTest => esplora_test().await,
    }
}

async fn backup_restore_test() -> anyhow::Result<()> {
    Box::pin(
        devimint::run_devfed_test().call(|dev_fed, process_mgr| async move {
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
    let old_gw_index = old_gw.gateway_index;
    old_gw.terminate().await?;
    info!(target: LOG_TEST, "Terminated Gateway");

    // Delete the gateway's database
    let data_dir: PathBuf = env::var(FM_DATA_DIR_ENV)
        .expect("Data dir is not set")
        .parse()
        .expect("Could not parse data dir");
    let gw_db = data_dir.join(gw_name.clone()).join("gatewayd.db");
    if gw_db.is_file() {
        // db is single file on redb
        remove_file(gw_db)?;
    } else {
        remove_dir_all(gw_db)?;
    }
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
    let new_gw = Gatewayd::new(&process_mgr, new_ln, old_gw_index).await?;
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
    almost_equal(
        ecash_balance.ecash_balance_msats.sats_round_down(),
        10_000_000,
        10,
    )
    .unwrap();
    let after_onchain_balance = gateway_balances.onchain_balance_sats;
    assert_eq!(before_onchain_balance, after_onchain_balance);
    info!(target: LOG_TEST, "Verified balances after recovery");

    Ok(new_gw)
}

/// Test that sets and verifies configurations within the gateway
#[allow(clippy::too_many_lines)]
async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    Box::pin(
        devimint::run_devfed_test()
            .num_feds(2)
            .call(|dev_fed, process_mgr| async move {
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

                // Get the federation's config and verify it parses correctly
                let config_val = cmd!(gw, "cfg", "client-config", "--federation-id", fed_id)
                    .out_json()
                    .await?;

                serde_json::from_value::<GatewayFedConfig>(config_val)?;

                // Spawn new federation
                let bitcoind = dev_fed.bitcoind().await?;
                let new_fed = Federation::new(
                    &process_mgr,
                    bitcoind.clone(),
                    false,
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

                let (default_base, default_ppm) = if gatewayd_version >= *VERSION_0_8_2 {
                    (0, 0)
                } else {
                    // v0.8.0 and v0.8.1
                    (2000, 3000)
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
                almost_equal(second_fed_balance_msat.msats, pegin_amount.msats, 10_000).unwrap();

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

                if gw.gatewayd_version >= *VERSION_0_10_0_ALPHA {
                    // Try to get the info over iroh
                    info!(target: LOG_TEST, gatewayd_version = %gw.gatewayd_version, "Getting info over iroh");
                    gw.get_info_iroh().await?;
                }

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
                almost_equal(
                    prev_receive_ecash_balance + 500_000,
                    after_receive_ecash_balance,
                    2_000,
                )
                .unwrap();
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

            let start = now() - Duration::from_secs(5 * 60);
            let end = now() + Duration::from_secs(5 * 60);
            info!(target: LOG_TEST, "Verifying list of transactions");
            let lnd_transactions = gw_lnd.list_transactions(start, end).await?;
            // One inbound and one outbound transaction
            assert_eq!(lnd_transactions.len(), 2);

            let ldk_transactions = gw_ldk.list_transactions(start, end).await?;
            assert_eq!(ldk_transactions.len(), 2);

            // Verify that transactions are filtered by time
            let start = now() - Duration::from_secs(10 * 60);
            let end = now() - Duration::from_secs(5 * 60);
            let lnd_transactions = gw_lnd.list_transactions(start, end).await?;
            assert_eq!(lnd_transactions.len(), 0);

            info!(target: LOG_TEST, "Testing paying Bolt12 Offers...");
            // TODO: investigate why the first BOLT12 payment attempt is expiring consistently
            poll_with_timeout("First BOLT12 payment", Duration::from_secs(30), || async {
                let offer_with_amount = gw_ldk_second.create_offer(Some(Amount::from_msats(10_000_000))).await.map_err(ControlFlow::Continue)?;
                gw_ldk.pay_offer(offer_with_amount, None).await.map_err(ControlFlow::Continue)?;
                assert!(get_transaction(gw_ldk_second, PaymentKind::Bolt12Offer, Amount::from_msats(10_000_000), PaymentStatus::Succeeded).await.is_some());
                Ok(())
            }).await?;

            let offer_without_amount = gw_ldk.create_offer(None).await?;
            gw_ldk_second.pay_offer(offer_without_amount.clone(), Some(Amount::from_msats(5_000_000))).await?;
            assert!(get_transaction(gw_ldk, PaymentKind::Bolt12Offer, Amount::from_msats(5_000_000), PaymentStatus::Succeeded).await.is_some());

            // Cannot pay an offer without an amount without specifying an amount
            gw_ldk_second.pay_offer(offer_without_amount.clone(), None).await.expect_err("Cannot pay amountless offer without specifying an amount");

            // Verify we can pay the offer again
            gw_ldk_second.pay_offer(offer_without_amount, Some(Amount::from_msats(3_000_000))).await?;
            assert!(get_transaction(gw_ldk, PaymentKind::Bolt12Offer, Amount::from_msats(3_000_000), PaymentStatus::Succeeded).await.is_some());

            info!(target: LOG_TEST, "Pegging-out gateways...");
            federation
                .pegout_gateways(500_000_000, gateways.clone())
                .await?;

            info!(target: LOG_TEST, "Testing sending onchain...");
            let bitcoind = dev_fed.bitcoind().await?;
            for gw in &gateways {
                let txid = gw
                    .send_onchain(dev_fed.bitcoind().await?, BitcoinAmountOrAll::All, 10)
                    .await?;
                bitcoind.poll_get_transaction(txid).await?;
            }

            info!(target: LOG_TEST, "Testing closing all channels...");

            // Gracefully close one of LND's channel's
            let gw_ldk_pubkey = gw_ldk.lightning_pubkey().await?;
            gw_lnd.close_channel(gw_ldk_pubkey, false).await?;

            // Force close LDK's channels
            gw_ldk_second.close_all_channels(true).await?;

            // Verify none of the channels are active
            for gw in gateways {
                let channels = gw.list_channels().await?;
                let active_channel = channels.into_iter().any(|chan| chan.is_active);
                assert!(!active_channel);
            }

            Ok(())
        })
        .await
}

async fn esplora_test() -> anyhow::Result<()> {
    let args = cli::CommonArgs::parse_from::<_, ffi::OsString>(vec![]);
    let (process_mgr, task_group) = cli::setup(args).await?;
    cleanup_on_exit(
        async {
            info!("Spawning bitcoind...");
            let bitcoind = Bitcoind::new(&process_mgr, false).await?;
            info!("Spawning esplora...");
            let _esplora = Esplora::new(&process_mgr, bitcoind).await?;
            let network = bitcoin::Network::from_str(&process_mgr.globals.FM_GATEWAY_NETWORK)
                .expect("Could not parse network");
            let esplora_port = process_mgr.globals.FM_PORT_ESPLORA.to_string();
            let esplora = default_esplora_server(network, Some(esplora_port));
            unsafe {
                std::env::remove_var("FM_BITCOIND_URL");
                std::env::set_var("FM_ESPLORA_URL", esplora.url.to_string());
            }
            info!("Spawning ldk gateway...");
            let ldk = Gatewayd::new(
                &process_mgr,
                LightningNode::Ldk {
                    name: "gateway-ldk-esplora".to_string(),
                    gw_port: process_mgr.globals.FM_PORT_GW_LDK,
                    ldk_port: process_mgr.globals.FM_PORT_LDK,
                    metrics_port: process_mgr.globals.FM_PORT_GW_LDK_METRICS,
                },
                0,
            )
            .await?;

            info!("Waiting for ldk gatewy to be ready...");
            poll("Waiting for LDK to be ready", || async {
                let info = ldk.get_info().await.map_err(ControlFlow::Continue)?;
                let state: String = serde_json::from_value(info["gateway_state"].clone())
                    .expect("Could not get gateway state");
                if state == "Running" {
                    Ok(())
                } else {
                    Err(ControlFlow::Continue(anyhow::anyhow!(
                        "Gateway not running"
                    )))
                }
            })
            .await?;

            ldk.get_ln_onchain_address().await?;
            info!(target:LOG_TEST, "ldk gateway successfully spawned and connected to esplora");
            Ok(())
        },
        task_group,
    )
    .await?;
    Ok(())
}

async fn get_transaction(
    gateway: &Gatewayd,
    kind: PaymentKind,
    amount: Amount,
    status: PaymentStatus,
) -> Option<PaymentDetails> {
    let transactions = gateway
        .list_transactions(
            now() - Duration::from_secs(5 * 60),
            now() + Duration::from_secs(5 * 60),
        )
        .await
        .ok()?;
    transactions.into_iter().find(|details| {
        details.payment_kind == kind && details.amount == amount && details.status == status
    })
}

/// Leaves the specified federation by issuing a `leave-fed` POST request to the
/// gateway.
async fn leave_federation(gw: &Gatewayd, fed_id: String, expected_scid: u64) -> anyhow::Result<()> {
    let leave_fed = cmd!(gw, "leave-fed", "--federation-id", fed_id.clone())
        .out_json()
        .await
        .expect("Leaving the federation failed");

    let federation_id: FederationId = serde_json::from_value(leave_fed["federation_id"].clone())?;
    assert_eq!(federation_id.to_string(), fed_id);

    let scid = serde_json::from_value::<u64>(leave_fed["config"]["federation_index"].clone())?;

    assert_eq!(scid, expected_scid);

    info!(target: LOG_TEST, federation_id = %fed_id, "Verified gateway left federation");
    Ok(())
}
