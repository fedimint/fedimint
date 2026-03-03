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
    UserAuthTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest { gateway_type } => Box::pin(config_test(gateway_type)).await,
        GatewayTest::BackupRestoreTest => Box::pin(backup_restore_test()).await,
        GatewayTest::LiquidityTest => Box::pin(liquidity_test()).await,
        GatewayTest::EsploraTest => esplora_test().await,
        GatewayTest::UserAuthTest => Box::pin(user_auth_test()).await,
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
                almost_equal(prev_send_ecash_balance - 500_000, after_send_ecash_balance, 512).expect("Balances were not almost equal");
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

            let start = now() - Duration::from_mins(5);
            let end = now() + Duration::from_mins(5);
            info!(target: LOG_TEST, "Verifying list of transactions");
            let lnd_transactions = gw_lnd.list_transactions(start, end).await?;
            // One inbound and one outbound transaction
            assert_eq!(lnd_transactions.len(), 2);

            let ldk_transactions = gw_ldk.list_transactions(start, end).await?;
            assert_eq!(ldk_transactions.len(), 2);

            // Verify that transactions are filtered by time
            let start = now() - Duration::from_mins(10);
            let end = now() - Duration::from_mins(5);
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

/// Test user management and authorization enforcement
#[allow(clippy::too_many_lines)]
async fn user_auth_test() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let federation = dev_fed.fed().await?;

            if !devimint::util::supports_lnv2() {
                info!(target: LOG_TEST, "LNv2 is not supported, which is necessary for LDK GW and user auth test");
                return Ok(());
            }

            let gw = dev_fed.gw_ldk_connected().await?;
            let gw_second = dev_fed.gw_ldk_second_connected().await?;

            // Peg in some sats for testing spend operations
            info!(target: LOG_TEST, "Pegging-in gateways for user auth test...");
            federation.pegin_gateways(10_000_000, vec![gw]).await?;

            let fed_id_str = federation.calculate_federation_id();
            let fed_id = FederationId::from_str(&fed_id_str)?;

            // ==================== Test User CRUD (as admin) ====================
            info!(target: LOG_TEST, "Testing user CRUD operations...");

            // Create users with different permissions
            let user1_password = "user1_secret_password";
            let user2_password = "user2_secret_password";
            let user3_password = "user3_secret_password";
            let user4_password = "user4_secret_password";
            let user5_password = "user5_secret_password";

            // User 1: Has SendLimit of 1,000,000 msats (1,000 sats)
            info!(target: LOG_TEST, "Creating user with SendLimit...");
            gw.client().create_user("test_user_1", user1_password, Some(1_000_000), false, false, false)
                .await?;

            // User 2: Has UserManagement permission (can manage other users)
            info!(target: LOG_TEST, "Creating user with UserManagement permission...");
            gw.client().create_user("test_user_2", user2_password, None, true, false, false)
                .await?;

            // User 3: Has no permissions (just authenticated, for deletion test)
            info!(target: LOG_TEST, "Creating user with no permissions...");
            gw.client().create_user("test_user_3", user3_password, None, false, false, false)
                .await?;

            // User 4: Has FederationManagement permission (can join/leave federations)
            info!(target: LOG_TEST, "Creating user with FederationManagement permission...");
            gw.client().create_user("test_user_4", user4_password, None, false, true, false)
                .await?;

            // User 5: Has FeeManagement permission (can modify fees)
            info!(target: LOG_TEST, "Creating user with FeeManagement permission...");
            gw.client().create_user("test_user_5", user5_password, None, false, false, true)
                .await?;

            // List users and verify all 5 exist
            info!(target: LOG_TEST, "Listing users...");
            let users = gw.client().list_users().await?;
            assert_eq!(users.users.len(), 5, "Expected 5 users");
            info!(target: LOG_TEST, "Verified 5 users exist");

            // Get specific user and verify details
            info!(target: LOG_TEST, "Getting specific user...");
            let user1 = gw
                .client()
                .get_user("test_user_1")
                .await?
                .expect("User should exist");
            assert_eq!(user1.username, "test_user_1");
            assert!(!user1.authorizations.is_empty(), "User should have authorizations");
            info!(target: LOG_TEST, "Verified user details");

            // Delete user 3
            info!(target: LOG_TEST, "Deleting user...");
            gw.client().delete_user("test_user_3").await?;

            // List users and verify only 4 remain
            let users = gw.client().list_users().await?;
            assert_eq!(users.users.len(), 4, "Expected 4 users after deletion");
            info!(target: LOG_TEST, "Verified user deletion");

            // ==================== Test Spend Limit Enforcement ====================
            info!(target: LOG_TEST, "Testing spend limit enforcement...");

            // Create a client for user 1 (has SendLimit of 1M msats)
            let user1_client = gw.client().as_user("test_user_1", user1_password);

            // Test 1: spend_ecash within limit should succeed
            info!(target: LOG_TEST, "Testing spend_ecash within limit...");
            let result = user1_client.spend_ecash(fed_id.clone(), 500_000).await;
            if let Err(ref e) = result {
                info!(target: LOG_TEST, "spend_ecash error: {:?}", e);
            }
            assert!(result.is_ok(), "spend_ecash within limit should succeed");
            info!(target: LOG_TEST, "spend_ecash within limit succeeded");

            // Test 2: spend_ecash exceeding limit should fail
            info!(target: LOG_TEST, "Testing spend_ecash exceeding limit...");
            let result = user1_client.spend_ecash(fed_id.clone(), 2_000_000).await;
            assert!(result.is_err(), "spend_ecash exceeding limit should fail");
            info!(target: LOG_TEST, "spend_ecash exceeding limit correctly rejected");

            // Test 3: withdraw exceeding limit should fail
            // (User has 1M msat limit, trying to withdraw more)
            info!(target: LOG_TEST, "Testing withdraw exceeding limit...");
            let bitcoind = dev_fed.bitcoind().await?;
            let address = bitcoind.get_new_address().await?;
            let result = user1_client
                .withdraw(
                    fed_id.clone(),
                    BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(2000)), // 2000 sats = 2M msats > 1M limit
                    &address.to_string(),
                )
                .await;
            assert!(result.is_err(), "withdraw exceeding limit should fail");
            info!(target: LOG_TEST, "withdraw exceeding limit correctly rejected");

            // Test 4: pay_invoice exceeding limit should fail
            info!(target: LOG_TEST, "Testing pay_invoice exceeding limit...");
            // Create an invoice for 2M msats (exceeds 1M limit)
            let large_invoice = gw_second.create_invoice(2_000_000).await?;
            let result = user1_client.pay_invoice(large_invoice).await;
            assert!(result.is_err(), "pay_invoice exceeding limit should fail");
            info!(target: LOG_TEST, "pay_invoice exceeding limit correctly rejected");

            // Test 5: send_onchain exceeding limit should fail
            info!(target: LOG_TEST, "Testing send_onchain exceeding limit...");
            let result = user1_client
                .send_onchain(
                    BitcoinAmountOrAll::Amount(bitcoin::Amount::from_sat(2000)), // 2000 sats = 2M msats > 1M limit
                    &address.to_string(),
                    10,
                )
                .await;
            assert!(result.is_err(), "send_onchain exceeding limit should fail");
            info!(target: LOG_TEST, "send_onchain exceeding limit correctly rejected");

            // Test 6: open_channel with push_amount exceeding limit should fail
            info!(target: LOG_TEST, "Testing open_channel with push_amount exceeding limit...");
            let other_pubkey = gw_second.lightning_pubkey().await?;
            let result = user1_client
                .open_channel(
                    &other_pubkey.to_string(),
                    "127.0.0.1:9736",
                    100_000, // channel size (not checked against limit)
                    2000,    // push_amount 2000 sats = 2M msats > 1M limit
                )
                .await;
            assert!(
                result.is_err(),
                "open_channel with push_amount exceeding limit should fail"
            );
            info!(target: LOG_TEST, "open_channel with push_amount exceeding limit correctly rejected");

            // Test 7: pay_offer exceeding limit should fail
            info!(target: LOG_TEST, "Testing pay_offer exceeding limit...");
            let offer = gw_second.create_offer(None).await?;
            let result = user1_client
                .pay_offer(&offer, Some(Amount::from_msats(2_000_000))) // 2M msats > 1M limit
                .await;
            assert!(result.is_err(), "pay_offer exceeding limit should fail");
            info!(target: LOG_TEST, "pay_offer exceeding limit correctly rejected");

            // ==================== Test User Without Spend Permission ====================
            info!(target: LOG_TEST, "Testing user without spend permission...");

            // User 2 has UserManagement but NOT SendLimit - should be rejected from spend endpoints
            let user2_client = gw.client().as_user("test_user_2", user2_password);
            let result = user2_client.spend_ecash(fed_id.clone(), 100_000).await;
            assert!(
                result.is_err(),
                "User without SendLimit should be rejected from spend_ecash"
            );
            info!(target: LOG_TEST, "User without SendLimit correctly rejected from spend endpoints");

            // ==================== Test User Management Permission ====================
            info!(target: LOG_TEST, "Testing user management permission enforcement...");

            // User 2 (has UserManagement) should be able to create users
            info!(target: LOG_TEST, "Testing create_user with UserManagement permission...");
            let result = user2_client
                .create_user("test_user_temp", "user_temp_password", None, false, false, false)
                .await;
            assert!(
                result.is_ok(),
                "User with UserManagement should be able to create users"
            );
            info!(target: LOG_TEST, "create_user with UserManagement succeeded");

            // Verify user was created
            let users = gw.client().list_users().await?;
            assert_eq!(
                users.users.len(),
                5,
                "Expected 5 users after creation by user_2"
            );

            // User 2 should be able to delete users
            info!(target: LOG_TEST, "Testing delete_user with UserManagement permission...");
            let result = user2_client.delete_user("test_user_temp").await;
            assert!(
                result.is_ok(),
                "User with UserManagement should be able to delete users"
            );
            info!(target: LOG_TEST, "delete_user with UserManagement succeeded");

            // User 1 (has SendLimit but NOT UserManagement) should NOT be able to create users
            info!(target: LOG_TEST, "Testing create_user without UserManagement permission...");
            let result = user1_client
                .create_user(
                    "test_user_temp2",
                    "user_temp2_password",
                    None,
                    false,
                    false,
                    false,
                )
                .await;
            assert!(
                result.is_err(),
                "User without UserManagement should NOT be able to create users"
            );
            info!(target: LOG_TEST, "create_user without UserManagement correctly rejected");

            // User 1 should NOT be able to delete users
            info!(target: LOG_TEST, "Testing delete_user without UserManagement permission...");
            let result = user1_client.delete_user("test_user_2").await;
            assert!(
                result.is_err(),
                "User without UserManagement should NOT be able to delete users"
            );
            info!(target: LOG_TEST, "delete_user without UserManagement correctly rejected");

            // ==================== Test Federation Management Permission ====================
            info!(target: LOG_TEST, "Testing federation management permission enforcement...");

            // User 4 (has FederationManagement) should be able to set fees
            // Note: We can't easily test connect/leave federation without affecting the test state,
            // so we'll test that users WITHOUT the permission are rejected

            // User 1 (has SendLimit but NOT FederationManagement) should NOT be able to leave federation
            info!(target: LOG_TEST, "Testing leave_federation without FederationManagement permission...");
            let result = user1_client.leave_federation(fed_id.clone()).await;
            assert!(
                result.is_err(),
                "User without FederationManagement should NOT be able to leave federation"
            );
            info!(target: LOG_TEST, "leave_federation without FederationManagement correctly rejected");

            // User 4 should be able to attempt leave_federation (will succeed in permission check,
            // but may fail for other reasons like balance - we just verify no permission error)
            // For safety, we won't actually leave the federation as it would break subsequent tests

            // ==================== Test Fee Management Permission ====================
            info!(target: LOG_TEST, "Testing fee management permission enforcement...");

            // User 1 (has SendLimit but NOT FeeManagement) should NOT be able to set fees
            info!(target: LOG_TEST, "Testing set_fees without FeeManagement permission...");
            let result = user1_client.set_fees(fed_id.clone(), 100, 1000).await;
            assert!(
                result.is_err(),
                "User without FeeManagement should NOT be able to set fees"
            );
            info!(target: LOG_TEST, "set_fees without FeeManagement correctly rejected");

            // User 5 (has FeeManagement) should be able to set fees
            info!(target: LOG_TEST, "Testing set_fees with FeeManagement permission...");
            let user5_client = gw.client().as_user("test_user_5", user5_password);
            let result = user5_client.set_fees(fed_id.clone(), 100, 1000).await;
            assert!(
                result.is_ok(),
                "User with FeeManagement should be able to set fees"
            );
            info!(target: LOG_TEST, "set_fees with FeeManagement succeeded");

            // ==================== Test Authorization over Iroh Endpoint ====================
            info!(target: LOG_TEST, "Testing authorization enforcement over iroh endpoint...");

            // Test spend limit enforcement over iroh - within limit should succeed
            info!(target: LOG_TEST, "Testing spend_ecash within limit via iroh...");
            let user1_iroh = gw.client().iroh().as_user("test_user_1", user1_password);
            let result = user1_iroh.spend_ecash(fed_id.clone(), 100_000).await;
            assert!(
                result.is_ok(),
                "spend_ecash within limit via iroh should succeed"
            );
            info!(target: LOG_TEST, "spend_ecash within limit via iroh succeeded");

            // Test spend limit enforcement over iroh - exceeding limit should fail
            info!(target: LOG_TEST, "Testing spend_ecash exceeding limit via iroh...");
            let result = user1_iroh.spend_ecash(fed_id.clone(), 2_000_000).await;
            assert!(
                result.is_err(),
                "spend_ecash exceeding limit via iroh should fail"
            );
            info!(target: LOG_TEST, "spend_ecash exceeding limit via iroh correctly rejected");

            // Test fee management permission over iroh - user without permission should fail
            info!(target: LOG_TEST, "Testing set_fees without FeeManagement permission via iroh...");
            let result = user1_iroh.set_fees(fed_id.clone(), 100, 1000).await;
            assert!(
                result.is_err(),
                "User without FeeManagement should NOT be able to set fees via iroh"
            );
            info!(target: LOG_TEST, "set_fees without FeeManagement via iroh correctly rejected");

            // Test fee management permission over iroh - user with permission should succeed
            info!(target: LOG_TEST, "Testing set_fees with FeeManagement permission via iroh...");
            let user5_iroh = gw.client().iroh().as_user("test_user_5", user5_password);
            let result = user5_iroh.set_fees(fed_id.clone(), 200, 2000).await;
            assert!(
                result.is_ok(),
                "User with FeeManagement should be able to set fees via iroh"
            );
            info!(target: LOG_TEST, "set_fees with FeeManagement via iroh succeeded");

            // Test admin-only endpoint (mnemonic) over iroh - admin should succeed
            info!(target: LOG_TEST, "Testing get_mnemonic as admin via iroh...");
            let result = gw.client().iroh().get_mnemonic().await;
            assert!(
                result.is_ok(),
                "Admin should be able to get mnemonic via iroh"
            );
            info!(target: LOG_TEST, "get_mnemonic as admin via iroh succeeded");

            // Test admin-only endpoint (mnemonic) over iroh - user should fail
            info!(target: LOG_TEST, "Testing get_mnemonic as user via iroh (should fail)...");
            let result = user5_iroh.get_mnemonic().await;
            assert!(
                result.is_err(),
                "User should NOT be able to get mnemonic via iroh (admin only)"
            );
            info!(target: LOG_TEST, "get_mnemonic as user via iroh correctly rejected");

            info!(target: LOG_TEST, "user_auth_test successful");
            Ok(())
        })
        .await
}

async fn get_transaction(
    gateway: &Gatewayd,
    kind: PaymentKind,
    amount: Amount,
    status: PaymentStatus,
) -> Option<PaymentDetails> {
    let transactions = gateway
        .list_transactions(
            now() - Duration::from_mins(5),
            now() + Duration::from_mins(5),
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
