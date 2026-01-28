use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, ffi};

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::Txid;
use clap::Subcommand;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_DISABLE_BASE_FEES_ENV, FM_ENABLE_MODULE_LNV2_ENV, is_env_var_set};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::net::api_announcement::SignedApiAnnouncement;
use fedimint_core::task::block_in_place;
use fedimint_core::util::backoff_util::aggressive_backoff;
use fedimint_core::util::{retry, write_overwrite_async};
use fedimint_core::{Amount, PeerId};
use fedimint_ln_client::LightningPaymentOutcome;
use fedimint_ln_client::cli::LnInvoiceResponse;
use fedimint_ln_server::common::LightningGatewayAnnouncement;
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use fedimint_lnv2_client::FinalSendOperationState;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_testing_core::node_type::LightningNodeType;
use futures::future::try_join_all;
use serde_json::json;
use substring::Substring;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::{fs, try_join};
use tracing::{debug, error, info};

use crate::cli::{CommonArgs, cleanup_on_exit, exec_user_command, setup};
use crate::envs::{FM_DATA_DIR_ENV, FM_DEVIMINT_RUN_DEPRECATED_TESTS_ENV, FM_PASSWORD_ENV};
use crate::federation::Client;
use crate::util::{LoadTestTool, ProcessManager, almost_equal, poll};
use crate::version_constants::{
    VERSION_0_8_2, VERSION_0_9_0_ALPHA, VERSION_0_10_0_ALPHA, VERSION_0_11_0_ALPHA,
};
use crate::{DevFed, Gatewayd, LightningNode, Lnd, cmd, dev_fed};

pub struct Stats {
    pub min: Duration,
    pub avg: Duration,
    pub median: Duration,
    pub p90: Duration,
    pub max: Duration,
    pub sum: Duration,
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "min: {:.1}s", self.min.as_secs_f32())?;
        write!(f, ", avg: {:.1}s", self.avg.as_secs_f32())?;
        write!(f, ", median: {:.1}s", self.median.as_secs_f32())?;
        write!(f, ", p90: {:.1}s", self.p90.as_secs_f32())?;
        write!(f, ", max: {:.1}s", self.max.as_secs_f32())?;
        write!(f, ", sum: {:.1}s", self.sum.as_secs_f32())?;
        Ok(())
    }
}

pub fn stats_for(mut v: Vec<Duration>) -> Stats {
    assert!(!v.is_empty());
    v.sort();
    let n = v.len();
    let min = v.first().unwrap().to_owned();
    let max = v.iter().last().unwrap().to_owned();
    let median = v[n / 2];
    let sum: Duration = v.iter().sum();
    let avg = sum / n as u32;
    let p90 = v[(n as f32 * 0.9) as usize];
    Stats {
        min,
        avg,
        median,
        p90,
        max,
        sum,
    }
}

pub async fn log_binary_versions() -> Result<()> {
    let fedimint_cli_version = cmd!(crate::util::get_fedimint_cli_path(), "--version")
        .out_string()
        .await?;
    info!(?fedimint_cli_version);
    let fedimint_cli_version_hash = cmd!(crate::util::get_fedimint_cli_path(), "version-hash")
        .out_string()
        .await?;
    info!(?fedimint_cli_version_hash);
    let gateway_cli_version = cmd!(crate::util::get_gateway_cli_path(), "--version")
        .out_string()
        .await?;
    info!(?gateway_cli_version);
    let gateway_cli_version_hash = cmd!(crate::util::get_gateway_cli_path(), "version-hash")
        .out_string()
        .await?;
    info!(?gateway_cli_version_hash);
    let fedimintd_version_hash = cmd!(crate::util::FedimintdCmd, "version-hash")
        .out_string()
        .await?;
    info!(?fedimintd_version_hash);
    let gatewayd_version_hash = cmd!(crate::util::Gatewayd, "version-hash")
        .out_string()
        .await?;
    info!(?gatewayd_version_hash);
    Ok(())
}

pub async fn latency_tests(
    dev_fed: DevFed,
    r#type: LatencyTest,
    upgrade_clients: Option<&UpgradeClients>,
    iterations: usize,
    assert_thresholds: bool,
) -> Result<()> {
    log_binary_versions().await?;

    let DevFed {
        fed,
        gw_lnd,
        gw_ldk,
        ..
    } = dev_fed;

    let max_p90_factor = 10.0;
    let p90_median_factor = 10;

    let client = match upgrade_clients {
        Some(c) => match r#type {
            LatencyTest::Reissue => c.reissue_client.clone(),
            LatencyTest::LnSend => c.ln_send_client.clone(),
            LatencyTest::LnReceive => c.ln_receive_client.clone(),
            LatencyTest::FmPay => c.fm_pay_client.clone(),
            LatencyTest::Restore => bail!("no reusable upgrade client for restore"),
        },
        None => fed.new_joined_client("latency-tests-client").await?,
    };

    let initial_balance_sats = 100_000_000;
    fed.pegin_client(initial_balance_sats, &client).await?;

    let lnd_gw_id = gw_lnd.gateway_id.clone();

    match r#type {
        LatencyTest::Reissue => {
            info!("Testing latency of reissue");
            let mut reissues = Vec::with_capacity(iterations);
            let amount_per_iteration_msats =
                // use a highest 2^-1 amount that fits, to try to use as many notes as possible
                ((initial_balance_sats * 1000 / iterations as u64).next_power_of_two() >> 1) - 1;
            for _ in 0..iterations {
                let notes = cmd!(client, "spend", amount_per_iteration_msats.to_string())
                    .out_json()
                    .await?["notes"]
                    .as_str()
                    .context("note must be a string")?
                    .to_owned();

                let start_time = Instant::now();
                cmd!(client, "reissue", notes).run().await?;
                reissues.push(start_time.elapsed());
            }
            let reissue_stats = stats_for(reissues);
            println!("### LATENCY REISSUE: {reissue_stats}");

            if assert_thresholds {
                assert!(reissue_stats.median < Duration::from_secs(10));
                assert!(reissue_stats.p90 < reissue_stats.median * p90_median_factor);
                assert!(
                    reissue_stats.max.as_secs_f64()
                        < reissue_stats.p90.as_secs_f64() * max_p90_factor
                );
            }
        }
        LatencyTest::LnSend => {
            info!("Testing latency of ln send");
            let mut ln_sends = Vec::with_capacity(iterations);
            for _ in 0..iterations {
                let invoice = gw_ldk.create_invoice(1_000_000).await?;
                let start_time = Instant::now();
                ln_pay(&client, invoice.to_string(), lnd_gw_id.clone()).await?;
                gw_ldk
                    .wait_bolt11_invoice(invoice.payment_hash().consensus_encode_to_vec())
                    .await?;
                ln_sends.push(start_time.elapsed());

                if crate::util::supports_lnv2() {
                    let invoice = gw_lnd.create_invoice(1_000_000).await?;

                    let start_time = Instant::now();

                    lnv2_send(&client, &gw_ldk.addr, &invoice.to_string()).await?;

                    ln_sends.push(start_time.elapsed());
                }
            }
            let ln_sends_stats = stats_for(ln_sends);
            println!("### LATENCY LN SEND: {ln_sends_stats}");

            if assert_thresholds {
                assert!(ln_sends_stats.median < Duration::from_secs(10));
                assert!(ln_sends_stats.p90 < ln_sends_stats.median * p90_median_factor);
                assert!(
                    ln_sends_stats.max.as_secs_f64()
                        < ln_sends_stats.p90.as_secs_f64() * max_p90_factor
                );
            }
        }
        LatencyTest::LnReceive => {
            info!("Testing latency of ln receive");
            let mut ln_receives = Vec::with_capacity(iterations);

            // give lnd some funds
            let invoice = gw_ldk.create_invoice(10_000_000).await?;
            ln_pay(&client, invoice.to_string(), lnd_gw_id.clone()).await?;

            for _ in 0..iterations {
                let invoice = ln_invoice(
                    &client,
                    Amount::from_msats(100_000),
                    "latency-over-lnd-gw".to_string(),
                    lnd_gw_id.clone(),
                )
                .await?
                .invoice;

                let start_time = Instant::now();
                gw_ldk
                    .pay_invoice(
                        Bolt11Invoice::from_str(&invoice).expect("Could not parse invoice"),
                    )
                    .await?;
                ln_receives.push(start_time.elapsed());

                if crate::util::supports_lnv2() {
                    let invoice = lnv2_receive(&client, &gw_lnd.addr, 100_000).await?.0;

                    let start_time = Instant::now();

                    gw_ldk.pay_invoice(invoice).await?;

                    ln_receives.push(start_time.elapsed());
                }
            }
            let ln_receives_stats = stats_for(ln_receives);
            println!("### LATENCY LN RECV: {ln_receives_stats}");

            if assert_thresholds {
                assert!(ln_receives_stats.median < Duration::from_secs(10));
                assert!(ln_receives_stats.p90 < ln_receives_stats.median * p90_median_factor);
                assert!(
                    ln_receives_stats.max.as_secs_f64()
                        < ln_receives_stats.p90.as_secs_f64() * max_p90_factor
                );
            }
        }
        LatencyTest::FmPay => {
            info!("Testing latency of internal payments within a federation");
            let mut fm_internal_pay = Vec::with_capacity(iterations);
            let sender = fed.new_joined_client("internal-swap-sender").await?;
            fed.pegin_client(10_000_000, &sender).await?;
            for _ in 0..iterations {
                let recv = cmd!(
                    client,
                    "ln-invoice",
                    "--amount=1000000msat",
                    "--description=internal-swap-invoice",
                    "--force-internal"
                )
                .out_json()
                .await?;

                let invoice = recv["invoice"]
                    .as_str()
                    .context("invoice must be string")?
                    .to_owned();
                let recv_op = recv["operation_id"]
                    .as_str()
                    .context("operation id must be string")?
                    .to_owned();

                let start_time = Instant::now();
                cmd!(sender, "ln-pay", invoice, "--force-internal")
                    .run()
                    .await?;

                cmd!(client, "await-invoice", recv_op).run().await?;
                fm_internal_pay.push(start_time.elapsed());
            }
            let fm_pay_stats = stats_for(fm_internal_pay);

            println!("### LATENCY FM PAY: {fm_pay_stats}");

            if assert_thresholds {
                assert!(fm_pay_stats.median < Duration::from_secs(15));
                assert!(fm_pay_stats.p90 < fm_pay_stats.median * p90_median_factor);
                assert!(
                    fm_pay_stats.max.as_secs_f64()
                        < fm_pay_stats.p90.as_secs_f64() * max_p90_factor
                );
            }
        }
        LatencyTest::Restore => {
            info!("Testing latency of restore");
            let backup_secret = cmd!(client, "print-secret").out_json().await?["secret"]
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap();
            if !is_env_var_set(FM_DEVIMINT_RUN_DEPRECATED_TESTS_ENV) {
                info!("Skipping tests, as in previous versions restore was very slow to test");
                return Ok(());
            }

            let start_time = Instant::now();
            let restore_client = Client::create("restore").await?;
            cmd!(
                restore_client,
                "restore",
                "--mnemonic",
                &backup_secret,
                "--invite-code",
                fed.invite_code()?
            )
            .run()
            .await?;
            let restore_time = start_time.elapsed();

            println!("### LATENCY RESTORE: {restore_time:?}");

            if assert_thresholds {
                if crate::util::is_backwards_compatibility_test() {
                    assert!(restore_time < Duration::from_secs(160));
                } else {
                    assert!(restore_time < Duration::from_secs(30));
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::struct_field_names)]
/// Clients reused for upgrade tests
pub struct UpgradeClients {
    reissue_client: Client,
    ln_send_client: Client,
    ln_receive_client: Client,
    fm_pay_client: Client,
}

async fn stress_test_fed(dev_fed: &DevFed, clients: Option<&UpgradeClients>) -> anyhow::Result<()> {
    use futures::FutureExt;

    // local environments can fail due to latency thresholds, however this shouldn't
    // cause the upgrade test to fail
    let assert_thresholds = false;

    // running only one iteration greatly improves the total test time while still
    // testing the same types of database entries
    let iterations = 1;

    // skip restore test for client upgrades, since restoring a client doesn't
    // require a persistent data dir
    let restore_test = if clients.is_some() {
        futures::future::ok(()).right_future()
    } else {
        latency_tests(
            dev_fed.clone(),
            LatencyTest::Restore,
            clients,
            iterations,
            assert_thresholds,
        )
        .left_future()
    };

    // tests are run in sequence so parallelism is controlled using gnu `parallel`
    // in `upgrade-test.sh`
    latency_tests(
        dev_fed.clone(),
        LatencyTest::Reissue,
        clients,
        iterations,
        assert_thresholds,
    )
    .await?;

    latency_tests(
        dev_fed.clone(),
        LatencyTest::LnSend,
        clients,
        iterations,
        assert_thresholds,
    )
    .await?;

    latency_tests(
        dev_fed.clone(),
        LatencyTest::LnReceive,
        clients,
        iterations,
        assert_thresholds,
    )
    .await?;

    latency_tests(
        dev_fed.clone(),
        LatencyTest::FmPay,
        clients,
        iterations,
        assert_thresholds,
    )
    .await?;

    restore_test.await?;

    Ok(())
}

pub async fn upgrade_tests(process_mgr: &ProcessManager, binary: UpgradeTest) -> Result<()> {
    match binary {
        UpgradeTest::Fedimintd { paths } => {
            if let Some(oldest_fedimintd) = paths.first() {
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", oldest_fedimintd) };
            } else {
                bail!("Must provide at least 1 binary path");
            }

            let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
            info!(
                "running first stress test for fedimintd version: {}",
                fedimintd_version
            );

            let mut dev_fed = dev_fed(process_mgr).await?;
            let client = dev_fed.fed.new_joined_client("test-client").await?;
            try_join!(stress_test_fed(&dev_fed, None), client.wait_session())?;

            for path in paths.iter().skip(1) {
                dev_fed.fed.restart_all_with_bin(process_mgr, path).await?;

                // stress test with all peers online
                try_join!(stress_test_fed(&dev_fed, None), client.wait_session())?;

                let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
                info!(
                    "### fedimintd passed stress test for version {}",
                    fedimintd_version
                );
            }
            info!("## fedimintd upgraded all binaries successfully");
        }
        UpgradeTest::FedimintCli { paths } => {
            let set_fedimint_cli_path = |path: &PathBuf| {
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var("FM_FEDIMINT_CLI_BASE_EXECUTABLE", path) };
                let fm_mint_client: String = format!(
                    "{fedimint_cli} --data-dir {datadir}",
                    fedimint_cli = crate::util::get_fedimint_cli_path().join(" "),
                    datadir = crate::vars::utf8(&process_mgr.globals.FM_CLIENT_DIR)
                );
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var("FM_MINT_CLIENT", fm_mint_client) };
            };

            if let Some(oldest_fedimint_cli) = paths.first() {
                set_fedimint_cli_path(oldest_fedimint_cli);
            } else {
                bail!("Must provide at least 1 binary path");
            }

            let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
            info!(
                "running first stress test for fedimint-cli version: {}",
                fedimint_cli_version
            );

            let dev_fed = dev_fed(process_mgr).await?;

            let wait_session_client = dev_fed.fed.new_joined_client("wait-session-client").await?;
            let reusable_upgrade_clients = UpgradeClients {
                reissue_client: dev_fed.fed.new_joined_client("reissue-client").await?,
                ln_send_client: dev_fed.fed.new_joined_client("ln-send-client").await?,
                ln_receive_client: dev_fed.fed.new_joined_client("ln-receive-client").await?,
                fm_pay_client: dev_fed.fed.new_joined_client("fm-pay-client").await?,
            };

            try_join!(
                stress_test_fed(&dev_fed, Some(&reusable_upgrade_clients)),
                wait_session_client.wait_session()
            )?;

            for path in paths.iter().skip(1) {
                set_fedimint_cli_path(path);
                let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
                info!("upgraded fedimint-cli to version: {}", fedimint_cli_version);
                try_join!(
                    stress_test_fed(&dev_fed, Some(&reusable_upgrade_clients)),
                    wait_session_client.wait_session()
                )?;
                info!(
                    "### fedimint-cli passed stress test for version {}",
                    fedimint_cli_version
                );
            }
            info!("## fedimint-cli upgraded all binaries successfully");
        }
        UpgradeTest::Gatewayd {
            gatewayd_paths,
            gateway_cli_paths,
        } => {
            if let Some(oldest_gatewayd) = gatewayd_paths.first() {
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var("FM_GATEWAYD_BASE_EXECUTABLE", oldest_gatewayd) };
            } else {
                bail!("Must provide at least 1 gatewayd path");
            }

            if let Some(oldest_gateway_cli) = gateway_cli_paths.first() {
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var("FM_GATEWAY_CLI_BASE_EXECUTABLE", oldest_gateway_cli) };
            } else {
                bail!("Must provide at least 1 gateway-cli path");
            }

            let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
            let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
            info!(
                ?gatewayd_version,
                ?gateway_cli_version,
                "running first stress test for gateway",
            );

            let mut dev_fed = dev_fed(process_mgr).await?;
            let client = dev_fed.fed.new_joined_client("test-client").await?;
            try_join!(stress_test_fed(&dev_fed, None), client.wait_session())?;

            for i in 1..gatewayd_paths.len() {
                info!(
                    "running stress test with gatewayd path {:?}",
                    gatewayd_paths.get(i)
                );
                let new_gatewayd_path = gatewayd_paths.get(i).expect("Not enough gatewayd paths");
                let new_gateway_cli_path = gateway_cli_paths
                    .get(i)
                    .expect("Not enough gateway-cli paths");

                let gateways = vec![&mut dev_fed.gw_lnd];

                try_join_all(gateways.into_iter().map(|gateway| {
                    gateway.restart_with_bin(process_mgr, new_gatewayd_path, new_gateway_cli_path)
                }))
                .await?;

                dev_fed.fed.await_gateways_registered().await?;
                try_join!(stress_test_fed(&dev_fed, None), client.wait_session())?;
                let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
                let gateway_cli_version = crate::util::GatewayCli::version_or_default().await;
                info!(
                    ?gatewayd_version,
                    ?gateway_cli_version,
                    "### gateway passed stress test for version",
                );
            }

            info!("## gatewayd upgraded all binaries successfully");
        }
    }
    Ok(())
}

pub async fn cli_tests(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
    let data_dir = env::var(FM_DATA_DIR_ENV)?;

    let DevFed {
        bitcoind,
        lnd,
        fed,
        gw_lnd,
        gw_ldk,
        ..
    } = dev_fed;

    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;

    let client = fed.new_joined_client("cli-tests-client").await?;
    let lnd_gw_id = gw_lnd.gateway_id.clone();

    cmd!(
        client,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/fedimintd-default-0/private.encrypt",
        "--out-file={data_dir}/fedimintd-default-0/config-plaintext.json"
    )
    .env(FM_PASSWORD_ENV, "pass")
    .run()
    .await?;

    cmd!(
        client,
        "dev",
        "config-encrypt",
        "--in-file={data_dir}/fedimintd-default-0/config-plaintext.json",
        "--out-file={data_dir}/fedimintd-default-0/config-2"
    )
    .env(FM_PASSWORD_ENV, "pass-foo")
    .run()
    .await?;

    cmd!(
        client,
        "dev",
        "config-decrypt",
        "--in-file={data_dir}/fedimintd-default-0/config-2",
        "--out-file={data_dir}/fedimintd-default-0/config-plaintext-2.json"
    )
    .env(FM_PASSWORD_ENV, "pass-foo")
    .run()
    .await?;

    let plaintext_one = fs::read_to_string(format!(
        "{data_dir}/fedimintd-default-0/config-plaintext.json"
    ))
    .await?;
    let plaintext_two = fs::read_to_string(format!(
        "{data_dir}/fedimintd-default-0/config-plaintext-2.json"
    ))
    .await?;
    anyhow::ensure!(
        plaintext_one == plaintext_two,
        "config-decrypt/encrypt failed"
    );

    fed.pegin_gateways(10_000_000, vec![&gw_lnd]).await?;

    let fed_id = fed.calculate_federation_id();
    let invite = fed.invite_code()?;

    let invite_code = cmd!(client, "dev", "decode", "invite-code", invite.clone())
        .out_json()
        .await?;

    let encode_invite_output = cmd!(
        client,
        "dev",
        "encode",
        "invite-code",
        format!("--url={}", invite_code["url"].as_str().unwrap()),
        "--federation_id={fed_id}",
        "--peer=0"
    )
    .out_json()
    .await?;

    anyhow::ensure!(
        encode_invite_output["invite_code"]
            .as_str()
            .expect("invite_code must be a string")
            == invite,
        "failed to decode and encode the client invite code",
    );

    // Test that LND and LDK can still send directly to each other

    // LND can pay LDK directly
    info!("Testing LND can pay LDK directly");
    let invoice = gw_ldk.create_invoice(1_200_000).await?;
    lnd.pay_bolt11_invoice(invoice.to_string()).await?;
    gw_ldk
        .wait_bolt11_invoice(invoice.payment_hash().consensus_encode_to_vec())
        .await?;

    // LDK can pay LND directly
    info!("Testing LDK can pay LND directly");
    let (invoice, payment_hash) = lnd.invoice(1_000_000).await?;
    gw_ldk
        .pay_invoice(Bolt11Invoice::from_str(&invoice).expect("Could not parse invoice"))
        .await?;
    gw_lnd.wait_bolt11_invoice(payment_hash).await?;

    // # Test the correct descriptor is used
    let config = cmd!(client, "config").out_json().await?;
    let guardian_count = config["global"]["api_endpoints"].as_object().unwrap().len();
    let wallet_module = config["modules"]
        .as_object()
        .unwrap()
        .values()
        .find(|m| m["kind"].as_str() == Some("wallet"))
        .expect("wallet module not found");
    let descriptor = wallet_module["peg_in_descriptor"]
        .as_str()
        .unwrap()
        .to_owned();

    info!("Testing generated descriptor for {guardian_count} guardian federation");
    if guardian_count == 1 {
        assert!(descriptor.contains("wpkh("));
    } else {
        assert!(descriptor.contains("wsh(sortedmulti("));
    }

    // # Client tests
    info!("Testing Client");

    // ## reissue e-cash
    info!("Testing reissuing e-cash");
    const CLIENT_START_AMOUNT: u64 = 5_000_000_000;
    const CLIENT_SPEND_AMOUNT: u64 = 1_100_000;

    let initial_client_balance = client.balance().await?;
    assert_eq!(initial_client_balance, 0);

    fed.pegin_client(CLIENT_START_AMOUNT / 1000, &client)
        .await?;

    // # Spend from client
    info!("Testing spending from client");
    let notes = cmd!(client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();

    let client_post_spend_balance = client.balance().await?;
    almost_equal(
        client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT,
        10_000,
    )
    .unwrap();

    // Test we can reissue our own notes
    cmd!(client, "reissue", notes).out_json().await?;

    let client_post_spend_balance = client.balance().await?;
    almost_equal(client_post_spend_balance, CLIENT_START_AMOUNT, 10_000).unwrap();

    let reissue_amount: u64 = 409_600;

    // Ensure that client can reissue after spending
    info!("Testing reissuing e-cash after spending");
    let _notes = cmd!(client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .as_object()
        .unwrap()
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap();

    let reissue_notes = cmd!(client, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();
    let client_reissue_amt = cmd!(client, "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // Ensure that client can reissue via module commands
    info!("Testing reissuing e-cash via module commands");
    let reissue_notes = cmd!(client, "spend", reissue_amount).out_json().await?["notes"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();
    let client_reissue_amt = cmd!(client, "module", "mint", "reissue", reissue_notes)
        .out_json()
        .await?
        .as_u64()
        .unwrap();
    assert_eq!(client_reissue_amt, reissue_amount);

    // LND gateway tests
    info!("Testing LND gateway");

    let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
    // Gatewayd did not support default fees before v0.8.2
    // In order for the amount tests to pass, we need to reliably set the fees to
    // 0,0.
    if gatewayd_version < *VERSION_0_8_2 {
        gw_lnd
            .set_federation_routing_fee(fed_id.clone(), 0, 0)
            .await?;

        // Poll until the client has heard about the updated fees
        poll("Waiting for LND GW fees to update", || async {
            let gateways_val = cmd!(client, "list-gateways")
                .out_json()
                .await
                .map_err(ControlFlow::Break)?;
            let gateways =
                serde_json::from_value::<Vec<LightningGatewayAnnouncement>>(gateways_val)
                    .expect("Could not deserialize");
            let fees = gateways
                .first()
                .expect("No gateway was registered")
                .info
                .fees;
            if fees.base_msat == 0 && fees.proportional_millionths == 0 {
                Ok(())
            } else {
                Err(ControlFlow::Continue(anyhow!("Fees have not been updated")))
            }
        })
        .await?;
    }

    // OUTGOING: fedimint-cli pays LDK via LND gateway
    if let Some(iroh_gw_id) = &gw_lnd.iroh_gateway_id
        && crate::util::FedimintCli::version_or_default().await >= *VERSION_0_10_0_ALPHA
    {
        info!("Testing outgoing payment from client to LDK via IROH LND Gateway");

        let initial_lnd_gateway_balance = gw_lnd.ecash_balance(fed_id.clone()).await?;
        let invoice = gw_ldk.create_invoice(2_000_000).await?;
        ln_pay(&client, invoice.to_string(), iroh_gw_id.clone()).await?;
        gw_ldk
            .wait_bolt11_invoice(invoice.payment_hash().consensus_encode_to_vec())
            .await?;

        // Assert balances changed by 2_000_000 msat (amount sent) + 0 msat (fee)
        let final_lnd_outgoing_gateway_balance = gw_lnd.ecash_balance(fed_id.clone()).await?;
        info!(
            ?final_lnd_outgoing_gateway_balance,
            "Final LND ecash balance after iroh payment"
        );
        anyhow::ensure!(
            almost_equal(
                final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance,
                2_000_000,
                1_000
            )
            .is_ok(),
            "LND Gateway balance changed by {} on LND outgoing IROH payment, expected 2_000_000",
            (final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance)
        );

        // Send the funds back over iroh
        let recv = ln_invoice(
            &client,
            Amount::from_msats(2_000_000),
            "iroh receive payment".to_string(),
            iroh_gw_id.clone(),
        )
        .await?;
        gw_ldk
            .pay_invoice(Bolt11Invoice::from_str(&recv.invoice).expect("Could not parse invoice"))
            .await?;
    }

    info!("Testing outgoing payment from client to LDK via LND gateway");
    let initial_lnd_gateway_balance = gw_lnd.ecash_balance(fed_id.clone()).await?;
    let invoice = gw_ldk.create_invoice(2_000_000).await?;
    ln_pay(&client, invoice.to_string(), lnd_gw_id.clone()).await?;
    let fed_id = fed.calculate_federation_id();
    gw_ldk
        .wait_bolt11_invoice(invoice.payment_hash().consensus_encode_to_vec())
        .await?;

    // Assert balances changed by 2_000_000 msat (amount sent) + 0 msat (fee)
    let final_lnd_outgoing_gateway_balance = gw_lnd.ecash_balance(fed_id.clone()).await?;
    anyhow::ensure!(
        almost_equal(
            final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance,
            2_000_000,
            3_000
        )
        .is_ok(),
        "LND Gateway balance changed by {} on LND outgoing payment, expected 2_000_000",
        (final_lnd_outgoing_gateway_balance - initial_lnd_gateway_balance)
    );

    // INCOMING: fedimint-cli receives from LDK via LND gateway
    info!("Testing incoming payment from LDK to client via LND gateway");
    let initial_lnd_incoming_client_balance = client.balance().await?;
    let recv = ln_invoice(
        &client,
        Amount::from_msats(1_300_000),
        "incoming-over-lnd-gw".to_string(),
        lnd_gw_id,
    )
    .await?;
    let invoice = recv.invoice;
    gw_ldk
        .pay_invoice(Bolt11Invoice::from_str(&invoice).expect("Could not parse invoice"))
        .await?;

    // Receive the ecash notes
    info!("Testing receiving ecash notes");
    let operation_id = recv.operation_id;
    cmd!(client, "await-invoice", operation_id.fmt_full())
        .run()
        .await?;

    // Assert balances changed by 1_300_000 msat
    let final_lnd_incoming_client_balance = client.balance().await?;
    let final_lnd_incoming_gateway_balance = gw_lnd.ecash_balance(fed_id.clone()).await?;
    anyhow::ensure!(
        almost_equal(
            final_lnd_incoming_client_balance - initial_lnd_incoming_client_balance,
            1_300_000,
            2_000
        )
        .is_ok(),
        "Client balance changed by {} on LND incoming payment, expected 1_300_000",
        (final_lnd_incoming_client_balance - initial_lnd_incoming_client_balance)
    );
    anyhow::ensure!(
        almost_equal(
            final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance,
            1_300_000,
            2_000
        )
        .is_ok(),
        "LND Gateway balance changed by {} on LND incoming payment, expected 1_300_000",
        (final_lnd_outgoing_gateway_balance - final_lnd_incoming_gateway_balance)
    );

    // TODO: test cancel/timeout

    // # Wallet tests
    // ## Deposit
    info!("Testing client deposit");
    let initial_walletng_balance = client.balance().await?;

    fed.pegin_client(100_000, &client).await?; // deposit in sats

    let post_deposit_walletng_balance = client.balance().await?;

    almost_equal(
        post_deposit_walletng_balance,
        initial_walletng_balance + 100_000_000, // deposit in msats
        2_000,
    )
    .unwrap();

    // ## Withdraw
    info!("Testing client withdraw");

    let initial_walletng_balance = client.balance().await?;

    let address = bitcoind.get_new_address().await?;
    let withdraw_res = cmd!(
        client,
        "withdraw",
        "--address",
        &address,
        "--amount",
        "50000 sat"
    )
    .out_json()
    .await?;

    let txid: Txid = withdraw_res["txid"].as_str().unwrap().parse().unwrap();
    let fees_sat = withdraw_res["fees_sat"].as_u64().unwrap();

    let tx_hex = bitcoind.poll_get_transaction(txid).await?;

    let tx = bitcoin::Transaction::consensus_decode_hex(&tx_hex, &ModuleRegistry::default())?;
    assert!(
        tx.output
            .iter()
            .any(|o| o.script_pubkey == address.script_pubkey() && o.value.to_sat() == 50000)
    );

    let post_withdraw_walletng_balance = client.balance().await?;
    let expected_wallet_balance = initial_walletng_balance - 50_000_000 - (fees_sat * 1000);

    almost_equal(
        post_withdraw_walletng_balance,
        expected_wallet_balance,
        4_000,
    )
    .unwrap();

    // # peer-version command
    let peer_0_fedimintd_version = cmd!(client, "dev", "peer-version", "--peer-id", "0")
        .out_json()
        .await?
        .get("version")
        .expect("Output didn't contain version")
        .as_str()
        .unwrap()
        .to_owned();

    assert_eq!(
        semver::Version::parse(&peer_0_fedimintd_version)?,
        fedimintd_version
    );

    info!("Checking initial announcements...");

    retry(
        "Check initial announcements",
        aggressive_backoff(),
        || async {
            // Give the client some time to fetch updates
            cmd!(client, "dev", "wait", "1").run().await?;

            // # API URL announcements
            let initial_announcements =
                serde_json::from_value::<BTreeMap<PeerId, SignedApiAnnouncement>>(
                    cmd!(client, "dev", "api-announcements",).out_json().await?,
                )
                .expect("failed to parse API announcements");

            if initial_announcements.len() < fed.members.len() {
                bail!(
                    "Not all announcements ready; got: {}, expected: {}",
                    initial_announcements.len(),
                    fed.members.len()
                )
            }

            if !initial_announcements
                .values()
                .all(|announcement| announcement.api_announcement.nonce == 0)
            {
                bail!("Not all announcements have their initial value");
            }
            Ok(())
        },
    )
    .await?;

    const NEW_API_URL: &str = "ws://127.0.0.1:4242";
    let new_announcement = serde_json::from_value::<SignedApiAnnouncement>(
        cmd!(
            client,
            "--our-id",
            "0",
            "--password",
            "pass",
            "admin",
            "sign-api-announcement",
            NEW_API_URL
        )
        .out_json()
        .await?,
    )
    .expect("Couldn't parse signed announcement");

    assert_eq!(
        new_announcement.api_announcement.nonce, 1,
        "Nonce did not increment correctly"
    );

    info!("Testing if the client syncs the announcement");
    let announcement = poll("Waiting for the announcement to propagate", || async {
        cmd!(client, "dev", "wait", "1")
            .run()
            .await
            .map_err(ControlFlow::Break)?;

        let new_announcements_peer2 =
            serde_json::from_value::<BTreeMap<PeerId, SignedApiAnnouncement>>(
                cmd!(client, "dev", "api-announcements",)
                    .out_json()
                    .await
                    .map_err(ControlFlow::Break)?,
            )
            .expect("failed to parse API announcements");

        let announcement = new_announcements_peer2[&PeerId::from(0)]
            .api_announcement
            .clone();
        if announcement.nonce == 1 {
            Ok(announcement)
        } else {
            Err(ControlFlow::Continue(anyhow!(
                "Haven't received updated announcement yet; nonce: {}",
                announcement.nonce
            )))
        }
    })
    .await?;

    assert_eq!(
        announcement.api_url,
        NEW_API_URL.parse().expect("valid URL")
    );

    Ok(())
}

pub async fn guardian_metadata_tests(dev_fed: DevFed) -> Result<()> {
    use fedimint_core::PeerId;
    use fedimint_core::net::guardian_metadata::SignedGuardianMetadata;

    log_binary_versions().await?;

    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
    let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;

    if fedimintd_version < *VERSION_0_11_0_ALPHA || fedimint_cli_version < *VERSION_0_11_0_ALPHA {
        info!("Skipping test for too old versions");
        return Ok(());
    }

    let DevFed { fed, .. } = dev_fed;

    let client = fed.internal_client().await?;

    info!("Checking initial guardian metadata...");

    retry(
        "Check initial guardian metadata",
        aggressive_backoff(),
        || async {
            // Give the client some time to fetch updates
            cmd!(client, "dev", "wait", "1").run().await?;

            let initial_metadata =
                serde_json::from_value::<BTreeMap<PeerId, SignedGuardianMetadata>>(
                    cmd!(client, "dev", "guardian-metadata",).out_json().await?,
                )
                .expect("failed to parse guardian metadata");

            if initial_metadata.len() < fed.members.len() {
                bail!(
                    "Not all guardian metadata ready; got: {}, expected: {}",
                    initial_metadata.len(),
                    fed.members.len()
                )
            }

            Ok(())
        },
    )
    .await?;

    const TEST_API_URL: &str = "ws://127.0.0.1:5000/";
    const TEST_PKARR_ID: &str = "test_pkarr_id_z32";

    let new_metadata = serde_json::from_value::<SignedGuardianMetadata>(
        cmd!(
            client,
            "--our-id",
            "0",
            "--password",
            "pass",
            "admin",
            "sign-guardian-metadata",
            "--api-urls",
            TEST_API_URL,
            "--pkarr-id",
            TEST_PKARR_ID
        )
        .out_json()
        .await?,
    )
    .expect("Couldn't parse signed guardian metadata");

    let parsed_metadata = new_metadata.guardian_metadata();

    assert_eq!(
        parsed_metadata.api_urls.first().unwrap().to_string(),
        TEST_API_URL,
        "API URL did not match"
    );

    assert_eq!(
        parsed_metadata.pkarr_id_z32, TEST_PKARR_ID,
        "Pkarr ID did not match"
    );

    info!("Testing if the client syncs the guardian metadata");
    let metadata = poll("Waiting for the guardian metadata to propagate", || async {
        cmd!(client, "dev", "wait", "1")
            .run()
            .await
            .map_err(ControlFlow::Break)?;

        let new_metadata_peer0 =
            serde_json::from_value::<BTreeMap<PeerId, SignedGuardianMetadata>>(
                cmd!(client, "dev", "guardian-metadata",)
                    .out_json()
                    .await
                    .map_err(ControlFlow::Break)?,
            )
            .expect("failed to parse guardian metadata");

        let metadata = new_metadata_peer0[&PeerId::from(0)].guardian_metadata();

        if metadata.api_urls.first().unwrap().to_string() == TEST_API_URL {
            Ok(metadata.clone())
        } else {
            Err(ControlFlow::Continue(anyhow!(
                "Haven't received updated guardian metadata yet"
            )))
        }
    })
    .await?;

    assert_eq!(
        metadata.pkarr_id_z32, TEST_PKARR_ID,
        "Pkarr ID did not propagate correctly"
    );

    Ok(())
}

pub async fn cli_load_test_tool_test(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;
    let data_dir = env::var(FM_DATA_DIR_ENV)?;
    let load_test_temp = PathBuf::from(data_dir).join("load-test-temp");
    dev_fed
        .fed
        .pegin_client(10_000, dev_fed.fed.internal_client().await?)
        .await?;
    let invite_code = dev_fed.fed.invite_code()?;
    dev_fed
        .gw_lnd
        .set_federation_routing_fee(dev_fed.fed.calculate_federation_id(), 0, 0)
        .await?;
    run_standard_load_test(&load_test_temp, &invite_code).await?;
    run_ln_circular_load_test(&load_test_temp, &invite_code).await?;
    Ok(())
}

pub async fn run_standard_load_test(
    load_test_temp: &Path,
    invite_code: &str,
) -> anyhow::Result<()> {
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "load-test",
        "--notes-per-user",
        "1",
        "--generate-invoice-with",
        "ldk-lightning-cli",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("2 reissue_notes"),
        "reissued different number notes than expected"
    );
    anyhow::ensure!(
        output.contains("1 gateway_pay_invoice"),
        "paid different number of invoices than expected"
    );
    Ok(())
}

pub async fn run_ln_circular_load_test(
    load_test_temp: &Path,
    invite_code: &str,
) -> anyhow::Result<()> {
    info!("Testing ln-circular-load-test with 'two-gateways' strategy");
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "two-gateways",
        "--test-duration-secs",
        "2",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_pay_invoice_success"),
        "missing invoice payment"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );

    info!("Testing ln-circular-load-test with 'partner-ping-pong' strategy");
    // Note: invite code isn't required because we already have an archive dir
    // Note: test-duration-secs needs to be greater than the timeout for
    // discover_api_version_set to work with degraded federations
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "partner-ping-pong",
        "--test-duration-secs",
        "6",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );

    info!("Testing ln-circular-load-test with 'self-payment' strategy");
    // Note invite code isn't required because we already have an archive dir
    let output = cmd!(
        LoadTestTool,
        "--archive-dir",
        load_test_temp.display(),
        "--users",
        "1",
        "ln-circular-load-test",
        "--strategy",
        "self-payment",
        "--test-duration-secs",
        "2",
        "--invite-code",
        invite_code
    )
    .out_string()
    .await?;
    println!("{output}");
    anyhow::ensure!(
        output.contains("gateway_create_invoice"),
        "missing invoice creation"
    );
    anyhow::ensure!(
        output.contains("gateway_payment_received_success"),
        "missing received payment"
    );
    Ok(())
}

pub async fn lightning_gw_reconnect_test(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> Result<()> {
    log_binary_versions().await?;

    let DevFed {
        bitcoind,
        lnd,
        fed,
        mut gw_lnd,
        gw_ldk,
        ..
    } = dev_fed;

    let client = fed
        .new_joined_client("lightning-gw-reconnect-test-client")
        .await?;

    info!("Pegging-in both gateways");
    fed.pegin_gateways(99_999, vec![&gw_lnd]).await?;

    // Drop other references to LND so that the test can kill it
    drop(lnd);

    tracing::info!("Stopping LND");
    // Verify that the gateway can query the lightning node for the pubkey and alias
    let mut info_cmd = cmd!(gw_lnd, "info");
    assert!(info_cmd.run().await.is_ok());

    // Verify that after stopping the lightning node, info no longer returns the
    // node public key since the lightning node is unreachable.
    let ln_type = gw_lnd.ln.ln_type().to_string();
    gw_lnd.stop_lightning_node().await?;
    let lightning_info = info_cmd.out_json().await?;
    if gw_lnd.gatewayd_version < *VERSION_0_10_0_ALPHA {
        let lightning_pub_key: Option<String> =
            serde_json::from_value(lightning_info["lightning_pub_key"].clone())?;

        assert!(lightning_pub_key.is_none());
    } else {
        let not_connected = lightning_info["lightning_info"].clone();
        assert!(not_connected.as_str().expect("ln info is not a string") == "not_connected");
    }

    // Restart LND
    tracing::info!("Restarting LND...");
    let new_lnd = Lnd::new(process_mgr, bitcoind.clone()).await?;
    gw_lnd.set_lightning_node(LightningNode::Lnd(new_lnd.clone()));

    tracing::info!("Retrying info...");
    const MAX_RETRIES: usize = 30;
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);

    for i in 0..MAX_RETRIES {
        match do_try_create_and_pay_invoice(&gw_lnd, &client, &gw_ldk).await {
            Ok(()) => break,
            Err(e) => {
                if i == MAX_RETRIES - 1 {
                    return Err(e);
                }
                tracing::debug!(
                    "Pay invoice for gateway {} failed with {e:?}, retrying in {} seconds (try {}/{MAX_RETRIES})",
                    ln_type,
                    RETRY_INTERVAL.as_secs(),
                    i + 1,
                );
                fedimint_core::task::sleep_in_test(
                    "paying invoice for gateway failed",
                    RETRY_INTERVAL,
                )
                .await;
            }
        }
    }

    info!(target: LOG_DEVIMINT, "lightning_reconnect_test: success");
    Ok(())
}

pub async fn gw_reboot_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    log_binary_versions().await?;

    let DevFed {
        bitcoind,
        lnd,
        fed,
        gw_lnd,
        gw_ldk,
        gw_ldk_second,
        ..
    } = dev_fed;

    let client = fed.new_joined_client("gw-reboot-test-client").await?;
    fed.pegin_client(10_000, &client).await?;

    // Wait for gateways to sync to chain
    let block_height = bitcoind.get_block_count().await? - 1;
    try_join!(
        gw_lnd.wait_for_block_height(block_height),
        gw_ldk.wait_for_block_height(block_height),
    )?;

    // Drop references to gateways so the test can kill them
    let lnd_gateway_id = gw_lnd.gateway_id.clone();
    let ldk_gateway_id = gw_ldk.gateway_id.clone();
    let gw_ldk_name = gw_ldk.gw_name.clone();
    let gw_ldk_port = gw_ldk.gw_port;
    let gw_lightning_port = gw_ldk.ldk_port;
    let gw_ldk_metrics_port = gw_ldk.metrics_port;
    drop(gw_lnd);
    drop(gw_ldk);

    // Verify that making a payment while the gateways are down does not result in
    // funds being stuck
    info!("Making payment while gateway is down");
    let initial_client_balance = client.balance().await?;
    let invoice = gw_ldk_second.create_invoice(3000).await?;
    ln_pay(&client, invoice.to_string(), lnd_gateway_id.clone())
        .await
        .expect_err("Expected ln-pay to return error because the gateway is not online");
    let new_client_balance = client.balance().await?;
    anyhow::ensure!(initial_client_balance == new_client_balance);

    // Reboot gateways with the same Lightning node instances
    info!("Rebooting gateways...");
    let (new_gw_lnd, new_gw_ldk) = try_join!(
        Gatewayd::new(process_mgr, LightningNode::Lnd(lnd.clone()), 0),
        Gatewayd::new(
            process_mgr,
            LightningNode::Ldk {
                name: gw_ldk_name,
                gw_port: gw_ldk_port,
                ldk_port: gw_lightning_port,
                metrics_port: gw_ldk_metrics_port,
            },
            1,
        )
    )?;

    let lnd_gateway_id = fedimint_core::secp256k1::PublicKey::from_str(&lnd_gateway_id)?;

    poll(
        "Waiting for LND Gateway Running state after reboot",
        || async {
            let mut new_lnd_cmd = cmd!(new_gw_lnd, "info");
            let lnd_value = new_lnd_cmd.out_json().await.map_err(ControlFlow::Continue)?;
            let reboot_gateway_state: String = serde_json::from_value(lnd_value["gateway_state"].clone()).context("invalid gateway state").map_err(ControlFlow::Break)?;
            let reboot_gateway_id = fedimint_core::secp256k1::PublicKey::from_str(&new_gw_lnd.gateway_id).expect("Could not convert public key");

            if reboot_gateway_state == "Running" {
                info!(target: LOG_DEVIMINT, "LND Gateway restarted, with auto-rejoin to federation");
                // Assert that the gateway info is the same as before the reboot
                assert_eq!(lnd_gateway_id, reboot_gateway_id);
                return Ok(());
            }
            Err(ControlFlow::Continue(anyhow!("gateway not running")))
        },
    )
    .await?;

    let ldk_gateway_id = fedimint_core::secp256k1::PublicKey::from_str(&ldk_gateway_id)?;
    poll(
        "Waiting for LDK Gateway Running state after reboot",
        || async {
            let mut new_ldk_cmd = cmd!(new_gw_ldk, "info");
            let ldk_value = new_ldk_cmd.out_json().await.map_err(ControlFlow::Continue)?;
            let reboot_gateway_state: String = serde_json::from_value(ldk_value["gateway_state"].clone()).context("invalid gateway state").map_err(ControlFlow::Break)?;
            let reboot_gateway_id = fedimint_core::secp256k1::PublicKey::from_str(&new_gw_ldk.gateway_id).expect("Could not convert public key");

            if reboot_gateway_state == "Running" {
                info!(target: LOG_DEVIMINT, "LDK Gateway restarted, with auto-rejoin to federation");
                // Assert that the gateway info is the same as before the reboot
                assert_eq!(ldk_gateway_id, reboot_gateway_id);
                return Ok(());
            }
            Err(ControlFlow::Continue(anyhow!("gateway not running")))
        },
    )
    .await?;

    info!(LOG_DEVIMINT, "gateway_reboot_test: success");
    Ok(())
}

pub async fn do_try_create_and_pay_invoice(
    gw_lnd: &Gatewayd,
    client: &Client,
    gw_ldk: &Gatewayd,
) -> anyhow::Result<()> {
    // Verify that after the lightning node has restarted, the gateway
    // automatically reconnects and can query the lightning node
    // info again.
    poll("Waiting for info to succeed after restart", || async {
        gw_lnd
            .lightning_pubkey()
            .await
            .map_err(ControlFlow::Continue)?;
        Ok(())
    })
    .await?;

    tracing::info!("Creating invoice....");
    let invoice = ln_invoice(
        client,
        Amount::from_msats(1000),
        "incoming-over-lnd-gw".to_string(),
        gw_lnd.gateway_id.clone(),
    )
    .await?
    .invoice;

    match &gw_lnd.ln.ln_type() {
        LightningNodeType::Lnd => {
            // Pay the invoice using LDK
            gw_ldk
                .pay_invoice(Bolt11Invoice::from_str(&invoice).expect("Could not parse invoice"))
                .await?;
        }
        LightningNodeType::Ldk => {
            unimplemented!("do_try_create_and_pay_invoice not implemented for LDK yet");
        }
    }
    Ok(())
}

async fn ln_pay(client: &Client, invoice: String, gw_id: String) -> anyhow::Result<String> {
    let value = cmd!(client, "ln-pay", invoice, "--gateway-id", gw_id,)
        .out_json()
        .await?;
    let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
    if fedimint_cli_version >= *VERSION_0_9_0_ALPHA {
        let outcome = serde_json::from_value::<LightningPaymentOutcome>(value)
            .expect("Could not deserialize Lightning payment outcome");
        match outcome {
            LightningPaymentOutcome::Success { preimage } => Ok(preimage),
            LightningPaymentOutcome::Failure { error_message } => {
                Err(anyhow!("Failed to pay lightning invoice: {error_message}"))
            }
        }
    } else {
        let operation_id = value["operation_id"]
            .as_str()
            .ok_or(anyhow!("Failed to pay invoice"))?
            .to_string();
        Ok(operation_id)
    }
}

async fn ln_invoice(
    client: &Client,
    amount: Amount,
    description: String,
    gw_id: String,
) -> anyhow::Result<LnInvoiceResponse> {
    let ln_response_val = cmd!(
        client,
        "ln-invoice",
        "--amount",
        amount.msats,
        format!("--description='{description}'"),
        "--gateway-id",
        gw_id,
    )
    .out_json()
    .await?;

    let ln_invoice_response: LnInvoiceResponse = serde_json::from_value(ln_response_val)?;

    Ok(ln_invoice_response)
}

async fn lnv2_receive(
    client: &Client,
    gateway: &str,
    amount: u64,
) -> anyhow::Result<(Bolt11Invoice, OperationId)> {
    Ok(serde_json::from_value::<(Bolt11Invoice, OperationId)>(
        cmd!(
            client,
            "module",
            "lnv2",
            "receive",
            amount,
            "--gateway",
            gateway
        )
        .out_json()
        .await?,
    )?)
}

async fn lnv2_send(client: &Client, gateway: &String, invoice: &String) -> anyhow::Result<()> {
    let send_op = serde_json::from_value::<OperationId>(
        cmd!(
            client,
            "module",
            "lnv2",
            "send",
            invoice,
            "--gateway",
            gateway
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
        serde_json::to_value(FinalSendOperationState::Success).expect("JSON serialization failed"),
    );

    Ok(())
}

pub async fn reconnect_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    log_binary_versions().await?;

    let DevFed {
        bitcoind, mut fed, ..
    } = dev_fed;

    bitcoind.mine_blocks(110).await?;
    fed.await_block_sync().await?;
    fed.await_all_peers().await?;

    // test a peer missing out on epochs and needing to rejoin
    fed.terminate_server(0).await?;
    fed.mine_then_wait_blocks_sync(100).await?;

    fed.start_server(process_mgr, 0).await?;
    fed.mine_then_wait_blocks_sync(100).await?;
    fed.await_all_peers().await?;
    info!(target: LOG_DEVIMINT, "Server 0 successfully rejoined!");
    fed.mine_then_wait_blocks_sync(100).await?;

    // now test what happens if consensus needs to be restarted
    fed.terminate_server(1).await?;
    fed.mine_then_wait_blocks_sync(100).await?;
    fed.terminate_server(2).await?;
    fed.terminate_server(3).await?;

    fed.start_server(process_mgr, 1).await?;
    fed.start_server(process_mgr, 2).await?;
    fed.start_server(process_mgr, 3).await?;

    fed.await_all_peers().await?;

    info!(target: LOG_DEVIMINT, "fm success: reconnect-test");
    Ok(())
}

pub async fn recoverytool_test(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;

    let DevFed { bitcoind, fed, .. } = dev_fed;

    let data_dir = env::var(FM_DATA_DIR_ENV)?;
    let client = fed.new_joined_client("recoverytool-test-client").await?;

    let mut fed_utxos_sats = HashSet::from([12_345_000, 23_456_000, 34_567_000]);
    let deposit_fees = fed.deposit_fees()?.msats / 1000;
    for sats in &fed_utxos_sats {
        // pegin_client automatically adds fees, so we need to counteract that
        fed.pegin_client(*sats - deposit_fees, &client).await?;
    }

    async fn withdraw(
        client: &Client,
        bitcoind: &crate::external::Bitcoind,
        fed_utxos_sats: &mut HashSet<u64>,
    ) -> Result<()> {
        let withdrawal_address = bitcoind.get_new_address().await?;
        let withdraw_res = cmd!(
            client,
            "withdraw",
            "--address",
            &withdrawal_address,
            "--amount",
            "5000 sat"
        )
        .out_json()
        .await?;

        let fees_sat = withdraw_res["fees_sat"]
            .as_u64()
            .expect("withdrawal should contain fees");
        let txid: Txid = withdraw_res["txid"]
            .as_str()
            .expect("withdrawal should contain txid string")
            .parse()
            .expect("txid should be parsable");
        let tx_hex = bitcoind.poll_get_transaction(txid).await?;

        let tx = bitcoin::Transaction::consensus_decode_hex(&tx_hex, &ModuleRegistry::default())?;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        let change_output = tx
            .output
            .iter()
            .find(|o| o.to_owned().script_pubkey != withdrawal_address.script_pubkey())
            .expect("withdrawal must have change output");
        assert!(fed_utxos_sats.insert(change_output.value.to_sat()));

        // Remove the utxo consumed from the withdrawal tx
        let total_output_sats = tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
        let input_sats = total_output_sats + fees_sat;
        assert!(fed_utxos_sats.remove(&input_sats));

        Ok(())
    }

    // Initiate multiple withdrawals in a session to verify the recoverytool
    // recognizes change outputs
    for _ in 0..2 {
        withdraw(&client, &bitcoind, &mut fed_utxos_sats).await?;
    }

    let total_fed_sats = fed_utxos_sats.iter().sum::<u64>();
    fed.finalize_mempool_tx().await?;

    // We are done transacting and save the current session id so we can wait for
    // the next session later on. We already save it here so that if in the meantime
    // a session is generated we don't wait for another.
    let last_tx_session = client.get_session_count().await?;

    info!("Recovering using utxos method");
    let output = cmd!(
        crate::util::Recoverytool,
        "--cfg",
        "{data_dir}/fedimintd-default-0",
        "utxos",
        "--db",
        "{data_dir}/fedimintd-default-0/database"
    )
    .env(FM_PASSWORD_ENV, "pass")
    .out_json()
    .await?;
    let outputs = output.as_array().context("expected an array")?;
    assert_eq!(outputs.len(), fed_utxos_sats.len());

    assert_eq!(
        outputs
            .iter()
            .map(|o| o["amount_sat"].as_u64().unwrap())
            .collect::<HashSet<_>>(),
        fed_utxos_sats
    );
    let utxos_descriptors = outputs
        .iter()
        .map(|o| o["descriptor"].as_str().unwrap())
        .collect::<HashSet<_>>();

    debug!(target: LOG_DEVIMINT, ?utxos_descriptors, "recoverytool descriptors using UTXOs method");

    let descriptors_json = serde_json::value::to_raw_value(&serde_json::Value::Array(vec![
        serde_json::Value::Array(
            utxos_descriptors
                .iter()
                .map(|d| {
                    json!({
                        "desc": d,
                        "timestamp": 0,
                    })
                })
                .collect(),
        ),
    ]))?;
    info!("Getting wallet balances before import");
    let bitcoin_client = bitcoind.wallet_client().await?;
    let balances_before = bitcoin_client.get_balances().await?;
    info!("Importing descriptors into bitcoin wallet");
    let request = bitcoin_client
        .get_jsonrpc_client()
        .build_request("importdescriptors", Some(&descriptors_json));
    let response = block_in_place(|| bitcoin_client.get_jsonrpc_client().send_request(request))?;
    response.check_error()?;
    info!("Getting wallet balances after import");
    let balances_after = bitcoin_client.get_balances().await?;
    let diff = balances_after.mine.immature + balances_after.mine.trusted
        - balances_before.mine.immature
        - balances_before.mine.trusted;

    // We need to wait for a session to be generated to make sure we have the signed
    // session outcome in our DB. If there ever is another problem here: wait for
    // fedimintd-0 specifically to acknowledge the session switch. In practice this
    // should be sufficiently synchronous though.
    client.wait_session_outcome(last_tx_session).await?;

    // Funds from descriptors should match the fed's utxos
    assert_eq!(diff.to_sat(), total_fed_sats);
    info!("Recovering using epochs method");

    let outputs = cmd!(
        crate::util::Recoverytool,
        "--cfg",
        "{data_dir}/fedimintd-default-0",
        "epochs",
        "--db",
        "{data_dir}/fedimintd-default-0/database"
    )
    .env(FM_PASSWORD_ENV, "pass")
    .out_json()
    .await?
    .as_array()
    .context("expected an array")?
    .clone();

    let epochs_descriptors = outputs
        .iter()
        .map(|o| o["descriptor"].as_str().unwrap())
        .collect::<HashSet<_>>();

    // nosemgrep: use-err-formatting
    debug!(target: LOG_DEVIMINT, ?epochs_descriptors, "recoverytool descriptors using epochs method");

    // Epochs method includes descriptors from spent outputs, so we only need to
    // verify the epochs method includes all available utxos
    for utxo_descriptor in utxos_descriptors {
        assert!(epochs_descriptors.contains(utxo_descriptor));
    }
    Ok(())
}

pub async fn guardian_backup_test(dev_fed: DevFed, process_mgr: &ProcessManager) -> Result<()> {
    const PEER_TO_TEST: u16 = 0;

    log_binary_versions().await?;

    let DevFed { mut fed, .. } = dev_fed;

    fed.await_all_peers()
        .await
        .expect("Awaiting federation coming online failed");

    let client = fed.new_joined_client("guardian-client").await?;
    let old_block_count = cmd!(
        client,
        "dev",
        "api",
        "--peer-id",
        PEER_TO_TEST.to_string(),
        "--module",
        "wallet",
        "block_count",
    )
    .out_json()
    .await?["value"]
        .as_u64()
        .expect("No block height returned");

    let backup_res = cmd!(
        client,
        "--our-id",
        PEER_TO_TEST.to_string(),
        "--password",
        "pass",
        "admin",
        "guardian-config-backup"
    )
    .out_json()
    .await?;
    let backup_hex = backup_res["tar_archive_bytes"]
        .as_str()
        .expect("expected hex string");
    let backup_tar = hex::decode(backup_hex).expect("invalid hex");

    let data_dir = fed
        .vars
        .get(&PEER_TO_TEST.into())
        .expect("peer not found")
        .FM_DATA_DIR
        .clone();

    fed.terminate_server(PEER_TO_TEST.into())
        .await
        .expect("could not terminate fedimintd");

    std::fs::remove_dir_all(&data_dir).expect("error deleting old datadir");
    std::fs::create_dir(&data_dir).expect("error creating new datadir");

    let write_file = |name: &str, data: &[u8]| {
        let mut file = std::fs::File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(data_dir.join(name))
            .expect("could not open file");
        file.write_all(data).expect("could not write file");
        file.flush().expect("could not flush file");
    };

    write_file("backup.tar", &backup_tar);
    write_file(
        fedimint_server::config::io::PLAINTEXT_PASSWORD,
        "pass".as_bytes(),
    );

    assert_eq!(
        std::process::Command::new("tar")
            .arg("-xf")
            .arg("backup.tar")
            .current_dir(data_dir)
            .spawn()
            .expect("error spawning tar")
            .wait()
            .expect("error extracting archive")
            .code(),
        Some(0),
        "tar failed"
    );

    fed.start_server(process_mgr, PEER_TO_TEST.into())
        .await
        .expect("could not restart fedimintd");

    poll("Peer catches up again", || async {
        let block_counts = all_peer_block_count(&client, fed.member_ids())
            .await
            .map_err(ControlFlow::Continue)?;
        let block_count = block_counts[&PeerId::from(PEER_TO_TEST)];

        info!("Caught up to block {block_count} of at least {old_block_count} (counts={block_counts:?})");

        if block_count < old_block_count {
            return Err(ControlFlow::Continue(anyhow!("Block count still behind")));
        }

        Ok(())
    })
    .await
    .expect("Peer didn't rejoin federation");

    Ok(())
}

async fn peer_block_count(client: &Client, peer: PeerId) -> Result<u64> {
    cmd!(
        client,
        "dev",
        "api",
        "--peer-id",
        peer.to_string(),
        "--module",
        "wallet",
        "block_count",
    )
    .out_json()
    .await?["value"]
        .as_u64()
        .context("No block height returned")
}

async fn all_peer_block_count(
    client: &Client,
    peers: impl Iterator<Item = PeerId>,
) -> Result<BTreeMap<PeerId, u64>> {
    let mut peer_heights = BTreeMap::new();
    for peer in peers {
        peer_heights.insert(peer, peer_block_count(client, peer).await?);
    }
    Ok(peer_heights)
}

pub async fn cannot_replay_tx_test(dev_fed: DevFed) -> Result<()> {
    log_binary_versions().await?;

    let DevFed { fed, .. } = dev_fed;

    let client = fed.new_joined_client("cannot-replay-client").await?;

    const CLIENT_START_AMOUNT: u64 = 10_000_000_000;
    const CLIENT_SPEND_AMOUNT: u64 = 5_000_000_000;

    let initial_client_balance = client.balance().await?;
    assert_eq!(initial_client_balance, 0);

    fed.pegin_client(CLIENT_START_AMOUNT / 1000, &client)
        .await?;

    // Fork client before spending ecash so we can later attempt a double spend
    let double_spend_client = client.new_forked("double-spender").await?;

    // Spend and reissue all ecash from the client
    let notes = cmd!(client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();

    let client_post_spend_balance = client.balance().await?;
    crate::util::almost_equal(
        client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT,
        10_000,
    )
    .unwrap();

    cmd!(client, "reissue", notes).out_json().await?;
    let client_post_reissue_balance = client.balance().await?;
    crate::util::almost_equal(client_post_reissue_balance, CLIENT_START_AMOUNT, 20_000).unwrap();

    // Attempt to spend the same ecash from the forked client
    let double_spend_notes = cmd!(double_spend_client, "spend", CLIENT_SPEND_AMOUNT)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();

    let double_spend_client_post_spend_balance = double_spend_client.balance().await?;
    crate::util::almost_equal(
        double_spend_client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT,
        10_000,
    )
    .unwrap();

    cmd!(double_spend_client, "reissue", double_spend_notes)
        .assert_error_contains("The transaction had an invalid input")
        .await?;

    let double_spend_client_post_spend_balance = double_spend_client.balance().await?;
    crate::util::almost_equal(
        double_spend_client_post_spend_balance,
        CLIENT_START_AMOUNT - CLIENT_SPEND_AMOUNT,
        10_000,
    )
    .unwrap();

    Ok(())
}

/// Test that client can init even when the federation is down
///
/// See <https://github.com/fedimint/fedimint/issues/6939>
pub async fn test_offline_client_initialization(
    dev_fed: DevFed,
    _process_mgr: &ProcessManager,
) -> Result<()> {
    log_binary_versions().await?;

    let DevFed { mut fed, .. } = dev_fed;

    // Ensure federation is properly initialized and all peers are online
    fed.await_all_peers().await?;

    // Create and join a client while all servers are online
    let client = fed.new_joined_client("offline-test-client").await?;

    // Verify client can get info while federation is online
    const INFO_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
    let online_info =
        fedimint_core::runtime::timeout(INFO_COMMAND_TIMEOUT, cmd!(client, "info").out_json())
            .await
            .context("Client info command timed out while federation was online")?
            .context("Client info command failed while federation was online")?;
    info!(target: LOG_DEVIMINT, "Client info while federation online: {:?}", online_info);

    // Shutdown all federation servers
    info!(target: LOG_DEVIMINT, "Shutting down all federation servers...");
    fed.terminate_all_servers().await?;

    // Wait a moment to ensure servers are fully shutdown
    fedimint_core::task::sleep_in_test("wait for federation shutdown", Duration::from_secs(2))
        .await;

    // Test that client info command still works with all servers offline
    // This should work because client info doesn't require server communication
    // for basic federation metadata and local state
    info!(target: LOG_DEVIMINT, "Testing client info command with all servers offline...");
    let offline_info =
        fedimint_core::runtime::timeout(INFO_COMMAND_TIMEOUT, cmd!(client, "info").out_json())
            .await
            .context("Client info command timed out while federation was offline")?
            .context("Client info command failed while federation was offline")?;

    info!(target: LOG_DEVIMINT, "Client info while federation offline: {:?}", offline_info);

    Ok(())
}

/// Test that client can detect federation config changes when servers restart
/// with new module configurations
///
/// This test starts a fresh federation, dumps the client config, then stops all
/// servers and modifies their configs by adding a new meta module instance. The
/// client should detect this configuration change after the servers restart.
pub async fn test_client_config_change_detection(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> Result<()> {
    log_binary_versions().await?;

    let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;

    if fedimint_cli_version < *VERSION_0_9_0_ALPHA {
        info!(target: LOG_DEVIMINT, "Skipping the test - fedimint-cli too old");
        return Ok(());
    }

    if fedimintd_version < *VERSION_0_9_0_ALPHA {
        info!(target: LOG_DEVIMINT, "Skipping the test - fedimintd too old");
        return Ok(());
    }

    let DevFed { mut fed, .. } = dev_fed;
    let peer_ids: Vec<_> = fed.member_ids().collect();

    fed.await_all_peers().await?;

    let client = fed.new_joined_client("config-change-test-client").await?;

    info!(target: LOG_DEVIMINT, "Getting initial client configuration...");
    let initial_config = cmd!(client, "config")
        .out_json()
        .await
        .context("Failed to get initial client config")?;

    info!(target: LOG_DEVIMINT, "Initial config modules: {:?}", initial_config["modules"].as_object().unwrap().keys().collect::<Vec<_>>());

    let data_dir = env::var(FM_DATA_DIR_ENV)?;
    let config_dir = PathBuf::from(&data_dir);

    // Shutdown all federation servers
    //
    // In prod. one would probably use a coordinated shutdown, just to be
    // careful, but since the change is only adding a new module that does
    // not submit CIs without user/admin interaction, there is
    // no way for the consensus to diverge.
    info!(target: LOG_DEVIMINT, "Shutting down all federation servers...");
    fed.terminate_all_servers().await?;

    // Wait for servers to fully shutdown
    fedimint_core::task::sleep_in_test("wait for federation shutdown", Duration::from_secs(2))
        .await;

    info!(target: LOG_DEVIMINT, "Modifying server configurations to add new meta module...");
    modify_server_configs(&config_dir, &peer_ids).await?;

    // Restart all servers with modified configs
    info!(target: LOG_DEVIMINT, "Restarting all servers with modified configurations...");
    for peer_id in peer_ids {
        fed.start_server(process_mgr, peer_id.to_usize()).await?;
    }

    // Wait for federation to stabilize
    info!(target: LOG_DEVIMINT, "Wait for peers to get back up");
    fed.await_all_peers().await?;

    // Use fedimint-cli dev wait to let the client read the new config in background
    info!(target: LOG_DEVIMINT, "Waiting for client to fetch updated configuration...");
    cmd!(client, "dev", "wait", "3")
        .run()
        .await
        .context("Failed to wait for client config update")?;

    // Test that client switched to the new config
    info!(target: LOG_DEVIMINT, "Testing client detection of configuration changes...");
    let updated_config = cmd!(client, "config")
        .out_json()
        .await
        .context("Failed to get updated client config")?;

    info!(target: LOG_DEVIMINT, "Updated config modules: {:?}", updated_config["modules"].as_object().unwrap().keys().collect::<Vec<_>>());

    // Verify that the configuration has changed (new meta module should be present)
    let initial_modules = initial_config["modules"].as_object().unwrap();
    let updated_modules = updated_config["modules"].as_object().unwrap();

    anyhow::ensure!(
        updated_modules.len() > initial_modules.len(),
        "Expected more modules in updated config. Initial: {}, Updated: {}",
        initial_modules.len(),
        updated_modules.len()
    );

    // Check if a new meta module was added
    let new_meta_module = updated_modules.iter().find(|(module_id, module_config)| {
        module_config["kind"].as_str() == Some("meta") && !initial_modules.contains_key(*module_id)
    });

    let new_meta_module_id = new_meta_module
        .map(|(id, _)| id)
        .with_context(|| "Expected to find new meta module in updated configuration")?;

    info!(target: LOG_DEVIMINT, "Found new meta module with id: {}", new_meta_module_id);

    // Verify client operations still work with the new configuration
    info!(target: LOG_DEVIMINT, "Verifying client operations work with new configuration...");
    let final_info = cmd!(client, "info")
        .out_json()
        .await
        .context("Client info command failed with updated configuration")?;

    info!(target: LOG_DEVIMINT, "Client successfully adapted to configuration changes: {:?}", final_info["federation_id"]);

    Ok(())
}

/// Modify server configuration files to add a new meta module instance
async fn modify_server_configs(config_dir: &Path, peer_ids: &[PeerId]) -> Result<()> {
    for &peer_id in peer_ids {
        modify_single_peer_config(config_dir, peer_id).await?;
    }
    Ok(())
}

/// Modify configuration files for a single peer to add a new meta module
/// instance
async fn modify_single_peer_config(config_dir: &Path, peer_id: PeerId) -> Result<()> {
    use fedimint_aead::{encrypted_write, get_encryption_key};
    use fedimint_core::core::ModuleInstanceId;
    use fedimint_server::config::io::read_server_config;
    use serde_json::Value;

    info!(target: LOG_DEVIMINT, %peer_id, "Modifying config for peer");
    let peer_dir = config_dir.join(format!("fedimintd-default-{}", peer_id.to_usize()));

    // Read consensus config
    let consensus_config_path = peer_dir.join("consensus.json");
    let consensus_config_content = fs::read_to_string(&consensus_config_path)
        .await
        .with_context(|| format!("Failed to read consensus config for peer {peer_id}"))?;

    let mut consensus_config: Value = serde_json::from_str(&consensus_config_content)
        .with_context(|| format!("Failed to parse consensus config for peer {peer_id}"))?;

    // Read the encrypted private config using the server config reader
    let password = "pass"; // Default password used in devimint
    let server_config = read_server_config(password, &peer_dir)
        .with_context(|| format!("Failed to read server config for peer {peer_id}"))?;

    // Find existing meta module in configs to use as template
    let consensus_config_modules = consensus_config["modules"]
        .as_object()
        .with_context(|| format!("No modules found in consensus config for peer {peer_id}"))?;

    // Look for existing meta module to copy its configuration
    let existing_meta_consensus = consensus_config_modules
        .values()
        .find(|module_config| module_config["kind"].as_str() == Some("meta"));

    let existing_meta_consensus = existing_meta_consensus
        .with_context(|| {
            format!("No existing meta module found in consensus config for peer {peer_id}")
        })?
        .clone();

    // Find existing meta module in private config
    let existing_meta_instance_id = server_config
        .consensus
        .modules
        .iter()
        .find(|(_, config)| config.kind.as_str() == "meta")
        .map(|(id, _)| *id)
        .with_context(|| {
            format!("No existing meta module found in private config for peer {peer_id}")
        })?;

    let existing_meta_private = server_config
        .private
        .modules
        .get(&existing_meta_instance_id)
        .with_context(|| format!("Failed to get existing meta private config for peer {peer_id}"))?
        .clone();

    // Find the highest existing module ID for the new module
    let last_existing_module_id = consensus_config_modules
        .keys()
        .filter_map(|id| id.parse::<u32>().ok())
        .max()
        .unwrap_or(0);

    let new_module_id = (last_existing_module_id + 1).to_string();
    let new_module_instance_id = ModuleInstanceId::from((last_existing_module_id + 1) as u16);

    info!(
        "Adding new meta module with id {} for peer {} (copying existing meta module config)",
        new_module_id, peer_id
    );

    // Add new meta module to consensus config by copying existing meta module
    if let Some(modules) = consensus_config["modules"].as_object_mut() {
        modules.insert(new_module_id.clone(), existing_meta_consensus);
    }

    // Add new meta module to private config
    let mut updated_private_config = server_config.private.clone();
    updated_private_config
        .modules
        .insert(new_module_instance_id, existing_meta_private);

    // Write back the modified consensus and client configs
    let updated_consensus_content = serde_json::to_string_pretty(&consensus_config)
        .with_context(|| format!("Failed to serialize consensus config for peer {peer_id}"))?;

    write_overwrite_async(&consensus_config_path, updated_consensus_content)
        .await
        .with_context(|| format!("Failed to write consensus config for peer {peer_id}"))?;

    // Write back the modified private config using direct encryption
    let salt = std::fs::read_to_string(peer_dir.join("private.salt"))
        .with_context(|| format!("Failed to read salt file for peer {peer_id}"))?;
    let key = get_encryption_key(password, &salt)
        .with_context(|| format!("Failed to get encryption key for peer {peer_id}"))?;

    let private_config_bytes = serde_json::to_string(&updated_private_config)
        .with_context(|| format!("Failed to serialize private config for peer {peer_id}"))?
        .into_bytes();

    // Remove the existing encrypted file first
    let encrypted_private_path = peer_dir.join("private.encrypt");
    if encrypted_private_path.exists() {
        std::fs::remove_file(&encrypted_private_path)
            .with_context(|| format!("Failed to remove old private config for peer {peer_id}"))?;
    }

    encrypted_write(private_config_bytes, &key, encrypted_private_path)
        .with_context(|| format!("Failed to write encrypted private config for peer {peer_id}"))?;

    info!("Successfully modified configs for peer {}", peer_id);
    Ok(())
}

pub async fn test_guardian_password_change(
    dev_fed: DevFed,
    process_mgr: &ProcessManager,
) -> Result<()> {
    log_binary_versions().await?;

    let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;

    if fedimint_cli_version < *VERSION_0_9_0_ALPHA {
        info!(target: LOG_DEVIMINT, "Skipping the test - fedimint-cli too old");
        return Ok(());
    }

    if fedimintd_version < *VERSION_0_9_0_ALPHA {
        info!(target: LOG_DEVIMINT, "Skipping the test - fedimintd too old");
        return Ok(());
    }

    let DevFed { mut fed, .. } = dev_fed;
    fed.await_all_peers().await?;

    let client = fed.new_joined_client("config-change-test-client").await?;

    let peer_id = 0;
    let data_dir: PathBuf = fed
        .vars
        .get(&peer_id)
        .expect("peer not found")
        .FM_DATA_DIR
        .clone();
    let file_exists = |file: &str| {
        let path = data_dir.join(file);
        path.exists()
    };
    let pre_password_file_exists = file_exists("password.secret");

    info!(target: LOG_DEVIMINT, "Changing password");
    cmd!(
        client,
        "--our-id",
        &peer_id.to_string(),
        "--password",
        "pass",
        "admin",
        "change-password",
        "foobar"
    )
    .run()
    .await
    .context("Failed to change guardian password")?;

    info!(target: LOG_DEVIMINT, "Waiting for fedimintd to be shut down");
    timeout(
        Duration::from_secs(30),
        fed.await_server_terminated(peer_id),
    )
    .await
    .context("Fedimintd didn't shut down in time after password change")??;

    info!(target: LOG_DEVIMINT, "Restarting fedimintd");
    fed.start_server(process_mgr, peer_id).await?;

    info!(target: LOG_DEVIMINT, "Wait for fedimintd to come online again");
    fed.await_peer(peer_id).await?;

    info!(target: LOG_DEVIMINT, "Testing password change worked");
    cmd!(
        client,
        "--our-id",
        &peer_id.to_string(),
        "--password",
        "foobar",
        "admin",
        "backup-statistics"
    )
    .run()
    .await
    .context("Failed to run guardian command with new password")?;

    assert!(!file_exists("private.bak"));
    assert!(!file_exists("password.bak"));
    assert!(!file_exists("private.new"));
    assert!(!file_exists("password.new"));
    assert_eq!(file_exists("password.secret"), pre_password_file_exists);

    Ok(())
}

#[derive(Subcommand)]
pub enum LatencyTest {
    Reissue,
    LnSend,
    LnReceive,
    FmPay,
    Restore,
}

#[derive(Subcommand)]
pub enum UpgradeTest {
    Fedimintd {
        #[arg(long, trailing_var_arg = true, num_args=1..)]
        paths: Vec<PathBuf>,
    },
    FedimintCli {
        #[arg(long, trailing_var_arg = true, num_args=1..)]
        paths: Vec<PathBuf>,
    },
    Gatewayd {
        #[arg(long, trailing_var_arg = true, num_args=1..)]
        gatewayd_paths: Vec<PathBuf>,
        #[arg(long, trailing_var_arg = true, num_args=1..)]
        gateway_cli_paths: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum TestCmd {
    /// `devfed` then checks the average latency of reissuing ecash, LN receive,
    /// and LN send
    LatencyTests {
        #[clap(subcommand)]
        r#type: LatencyTest,

        #[arg(long, default_value = "10")]
        iterations: usize,
    },
    /// `devfed` then kills and restarts most of the Guardian nodes in a 4 node
    /// fedimint
    ReconnectTest,
    /// `devfed` then tests a bunch of the fedimint-cli commands
    CliTests,
    /// `devfed` then tests guardian metadata functionality
    GuardianMetadataTests,
    /// `devfed` then calls binary `fedimint-load-test-tool`. See
    /// `LoadTestArgs`.
    LoadTestToolTest,
    /// `devfed` then pegin LND Gateway. Kill the LN node,
    /// restart it, rejjoin fedimint and test payments still work
    LightningReconnectTest,
    /// `devfed` then reboot gateway daemon for both LDK and LND. Test
    /// afterward.
    GatewayRebootTest,
    /// `devfed` then tests if the recovery tool is able to do a basic recovery
    RecoverytoolTests,
    /// `devfed` then spawns faucet for wasm tests
    WasmTestSetup {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Restore guardian from downloaded backup
    GuardianBackup,
    /// `devfed` then tests that spent ecash cannot be double spent
    CannotReplayTransaction,
    /// Tests that client info commands work when all federation servers are
    /// offline
    TestOfflineClientInitialization,
    /// Tests that client can detect federation config changes when servers
    /// restart with new module configurations
    TestClientConfigChangeDetection,
    /// Tests that guardian password change works and the guardian can restart
    /// afterwards
    TestGuardianPasswordChange,
    /// Test upgrade paths for a given binary
    UpgradeTests {
        #[clap(subcommand)]
        binary: UpgradeTest,
        #[arg(long)]
        lnv2: String,
    },
}

pub async fn handle_command(cmd: TestCmd, common_args: CommonArgs) -> Result<()> {
    match cmd {
        TestCmd::WasmTestSetup { exec } => {
            let (process_mgr, task_group) = setup(common_args).await?;
            let main = {
                let task_group = task_group.clone();
                async move {
                    let dev_fed = dev_fed(&process_mgr).await?;
                    let gw_lnd = dev_fed.gw_lnd.clone();
                    let fed = dev_fed.fed.clone();
                    gw_lnd
                        .set_federation_routing_fee(dev_fed.fed.calculate_federation_id(), 0, 0)
                        .await?;
                    task_group.spawn_cancellable("faucet", async move {
                        if let Err(err) = crate::faucet::run(
                            &dev_fed,
                            format!("0.0.0.0:{}", process_mgr.globals.FM_PORT_FAUCET),
                            process_mgr.globals.FM_PORT_GW_LND,
                        )
                        .await
                        {
                            error!("Error spawning faucet: {err}");
                        }
                    });
                    try_join!(fed.pegin_gateways(30_000, vec![&gw_lnd]), async {
                        poll("waiting for faucet startup", || async {
                            TcpStream::connect(format!(
                                "127.0.0.1:{}",
                                process_mgr.globals.FM_PORT_FAUCET
                            ))
                            .await
                            .context("connect to faucet")
                            .map_err(ControlFlow::Continue)
                        })
                        .await?;
                        Ok(())
                    },)?;
                    if let Some(exec) = exec {
                        exec_user_command(exec).await?;
                        task_group.shutdown();
                    }
                    Ok::<_, anyhow::Error>(())
                }
            };
            cleanup_on_exit(main, task_group).await?;
        }
        TestCmd::LatencyTests { r#type, iterations } => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            latency_tests(dev_fed, r#type, None, iterations, true).await?;
        }
        TestCmd::ReconnectTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            reconnect_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::CliTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_tests(dev_fed).await?;
        }
        TestCmd::GuardianMetadataTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            guardian_metadata_tests(dev_fed).await?;
        }
        TestCmd::LoadTestToolTest => {
            // For the load test tool test, explicitly disable mint base fees
            unsafe { std::env::set_var(FM_DISABLE_BASE_FEES_ENV, "1") };

            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cli_load_test_tool_test(dev_fed).await?;
        }
        TestCmd::LightningReconnectTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            lightning_gw_reconnect_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::GatewayRebootTest => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            gw_reboot_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::RecoverytoolTests => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            recoverytool_test(dev_fed).await?;
        }
        TestCmd::GuardianBackup => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            guardian_backup_test(dev_fed, &process_mgr).await?;
        }
        TestCmd::CannotReplayTransaction => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            cannot_replay_tx_test(dev_fed).await?;
        }
        TestCmd::TestOfflineClientInitialization => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            test_offline_client_initialization(dev_fed, &process_mgr).await?;
        }
        TestCmd::TestClientConfigChangeDetection => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            test_client_config_change_detection(dev_fed, &process_mgr).await?;
        }
        TestCmd::TestGuardianPasswordChange => {
            let (process_mgr, _) = setup(common_args).await?;
            let dev_fed = dev_fed(&process_mgr).await?;
            test_guardian_password_change(dev_fed, &process_mgr).await?;
        }
        TestCmd::UpgradeTests { binary, lnv2 } => {
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe { std::env::set_var(FM_ENABLE_MODULE_LNV2_ENV, lnv2) };
            let (process_mgr, _) = setup(common_args).await?;
            Box::pin(upgrade_tests(&process_mgr, binary)).await?;
        }
    }
    Ok(())
}
