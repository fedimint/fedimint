use std::path::PathBuf;

use anyhow::{Context, ensure};
use clap::Parser;
use devimint::version_constants::VERSION_0_11_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::NumPeers;
use fedimint_walletv2_tests::{
    FinalSendState, await_consensus_block_count, await_no_pending_txs, await_receive,
    ensure_federation_total_value, get_deposit_address, module_is_present,
    report_frost_finalization_stats, spawn_block_miner, tx_chain,
};
use tokio::try_join;
use tracing::info;

#[derive(Parser)]
struct Opts {
    /// Federation sizes to test, e.g. `--fed-sizes 4,7,11`. For each size the
    /// test runs at every offline-guardian level from `0` up to the
    /// fault-tolerance threshold `f = (size - 1) / 3`. Each combination is run
    /// in its own child process.
    #[arg(long, value_delimiter = ',')]
    fed_sizes: Vec<usize>,

    /// Internal worker argument: run the test against a single federation of
    /// this size. Set by the driver when spawning child processes; not intended
    /// to be passed directly.
    #[arg(long, hide = true)]
    fed_size: Option<usize>,

    /// Internal worker argument: number of guardians to take offline. Set by
    /// the driver when spawning child processes; not intended to be passed
    /// directly.
    #[arg(long, hide = true)]
    offline_nodes: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    // Worker mode: run a single `(fed_size, offline_nodes)` combination. The
    // driver re-invokes this binary in this mode, once per combination.
    // `run_devfed_test` (called below) initializes the tracing subscriber, so we
    // must not initialize it ourselves here.
    if let Some(fed_size) = opts.fed_size {
        let offline_nodes = opts
            .offline_nodes
            .context("--offline-nodes is required alongside --fed-size")?;

        return run_single_federation(fed_size, offline_nodes).await;
    }

    // Driver mode: spawn a child process for every combination. A separate
    // process per federation is required because the tracing subscriber can only
    // be initialized once per process, so we cannot run multiple federations
    // back-to-back in a single process.
    ensure!(
        !opts.fed_sizes.is_empty(),
        "provide at least one federation size via --fed-sizes"
    );

    fedimint_logging::TracingSetup::default().init()?;

    run_driver(&opts.fed_sizes).await
}

/// Re-invokes this binary once per `(fed_size, offline_nodes)` combination,
/// covering every offline level from `0` up to `max_evil()` for each federation
/// size. Fails on the first combination whose worker process exits non-zero.
async fn run_driver(fed_sizes: &[usize]) -> anyhow::Result<()> {
    let current_exe = std::env::current_exe().context("resolving current executable path")?;

    // Each worker gets its own test directory so federations don't clobber each
    // other's data and so per-combination logs are easy to find. Use any
    // operator-provided `FM_TEST_DIR` as the base, otherwise a per-run temp dir.
    let base_test_dir = std::env::var_os("FM_TEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("devimint-frost-{}", std::process::id()))
        });

    for &fed_size in fed_sizes {
        let max_evil = NumPeers::from(fed_size).max_evil();

        for offline_nodes in 0..=max_evil {
            info!(
                fed_size,
                offline_nodes, max_evil, "Running FROST test combination"
            );

            let test_dir = base_test_dir.join(format!("fed{fed_size}-offline{offline_nodes}"));

            let status = tokio::process::Command::new(&current_exe)
                .arg("--fed-size")
                .arg(fed_size.to_string())
                .arg("--offline-nodes")
                .arg(offline_nodes.to_string())
                .env("FM_TEST_DIR", &test_dir)
                .status()
                .await
                .with_context(|| {
                    format!(
                        "spawning worker for fed_size={fed_size}, offline_nodes={offline_nodes}"
                    )
                })?;

            ensure!(
                status.success(),
                "FROST test failed for fed_size={fed_size}, offline_nodes={offline_nodes} \
                 (worker exited with {status})"
            );
        }
    }

    info!("All Wallet V2 FROST test combinations passed");

    Ok(())
}

/// Runs the peg-in / peg-out test against a single federation of `fed_size`
/// guardians with `offline_nodes` of them taken offline.
async fn run_single_federation(fed_size: usize, offline_nodes: usize) -> anyhow::Result<()> {
    // A BFT federation of `n` guardians tolerates at most `f = (n - 1) / 3`
    // offline guardians; beyond that the remaining `n - f` guardians fall below
    // the consensus (and FROST signing) threshold and the federation stalls.
    let num_peers = NumPeers::from(fed_size);
    ensure!(
        offline_nodes <= num_peers.max_evil(),
        "{} offline guardians exceeds the fault-tolerance threshold f = {} for a \
         {}-guardian federation; at least {} guardians must stay online",
        offline_nodes,
        num_peers.max_evil(),
        fed_size,
        num_peers.threshold(),
    );

    // Spawn a federation with walletv2 enabled (using the FROST wallet
    // descriptor) and walletv1 disabled. `run_devfed_test` reads the federation
    // size from `FM_FED_SIZE` and the number of guardians to shut down from
    // `FM_OFFLINE_NODES` (applied automatically via `degrade_federation`).
    unsafe { std::env::set_var("FM_FED_SIZE", fed_size.to_string()) };
    unsafe { std::env::set_var("FM_OFFLINE_NODES", offline_nodes.to_string()) };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "true") };
    unsafe { std::env::set_var("FM_WALLETV2_DESCRIPTOR", "frost") };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLET", "false") };
    unsafe { std::env::set_var("FM_WALLETV2_FROST_NONCE_BUFFER_TARGET", "3") };

    devimint::run_devfed_test()
        .call(move |dev_fed, _process_mgr| async move {
            info!(fed_size, offline_nodes, "Starting FROST federation test");

            let fedimint_cli_version = util::FedimintCli::version_or_default().await;
            let fedimintd_version = util::FedimintdCmd::version_or_default().await;

            if fedimint_cli_version < *VERSION_0_11_0_ALPHA {
                info!(%fedimint_cli_version, "Version did not support walletv2 module, skipping");
                return Ok(());
            }

            if fedimintd_version < *VERSION_0_11_0_ALPHA {
                info!(%fedimintd_version, "Version did not support walletv2 module, skipping");
                return Ok(());
            }

            let (fed, bitcoind) = try_join!(dev_fed.fed(), dev_fed.bitcoind())?;

            let client = fed.new_joined_client("walletv2-frost-test-client").await?;

            info!("Verify that walletv2 is enabled and walletv1 is disabled...");

            ensure!(
                !module_is_present(&client, "wallet").await?,
                "walletv1 module should not be present"
            );

            ensure!(
                module_is_present(&client, "walletv2").await?,
                "walletv2 module should be present"
            );

            // Spawn a background task that continuously mines blocks. This simulates
            // real bitcoin block production and prevents deadlocks where pending
            // federation bitcoin transactions block deposit claims via congestion
            // control while no blocks are being mined to confirm them.
            let block_miner = spawn_block_miner(bitcoind.clone());

            // We need the consensus block count to reach a non-zero value before we
            // send in any funds such that the UTXO is tracked by the federation.
            info!("Wait for the consensus to reach block count one");

            await_consensus_block_count(&client, 1).await?;

            // The first deposit into an empty wallet is stored directly as the
            // wallet UTXO, without a FROST-signed transaction (so no finalization
            // stat). It just seeds the wallet with a UTXO to consolidate against.
            info!("Seed the federation wallet with an initial deposit...");

            let (seed_address, seed_position) = get_deposit_address(&client).await?;

            bitcoind.send_to(seed_address.to_string(), 100_000).await?;

            await_receive(&client, seed_position).await?;

            // A deposit into a non-empty wallet sweeps the existing UTXO and the
            // new deposit into a single consolidation transaction, which IS
            // FROST-signed — so it produces a finalization stat.
            info!("Deposit again to trigger a FROST-signed consolidation tx...");

            let (consolidation_address, consolidation_position) =
                get_deposit_address(&client).await?;

            bitcoind
                .send_to(consolidation_address.to_string(), 100_000)
                .await?;

            await_receive(&client, consolidation_position).await?;

            ensure_federation_total_value(&client, 180_000).await?;

            // Once there are no pending transactions, the consolidation tx has
            // finalized and every online guardian has deterministically recorded
            // its FROST finalization stat.
            await_no_pending_txs(&client).await?;

            // The consolidation tx is the only federation tx so far (the peg-out
            // hasn't happened yet), so it's the last entry in the tx chain.
            let consolidation_txid = tx_chain(&client)
                .await?
                .last()
                .context("expected a consolidation tx after the second peg-in")?
                .txid;

            report_frost_finalization_stats(
                &client,
                "peg-in (consolidation)",
                consolidation_txid,
                fed_size,
                offline_nodes,
            )
            .await?;

            info!("Peg funds back out to an on-chain address...");

            let withdraw_address = bitcoind.get_new_address().await?;

            let value = cmd!(
                client,
                "module",
                "walletv2",
                "send",
                withdraw_address,
                "50000 sat"
            )
            .out_json()
            .await?;

            let FinalSendState::Success(txid) = serde_json::from_value(value)? else {
                panic!("Peg-out send operation failed");
            };

            // `await_no_pending_txs` only returns once the peg-out has been
            // signed, broadcast, and confirmed (it polls the unsigned +
            // unconfirmed sets), which also guarantees the FROST finalization
            // stat has been recorded — so no separate on-chain poll is needed.
            await_no_pending_txs(&client).await?;

            report_frost_finalization_stats(&client, "peg-out", txid, fed_size, offline_nodes)
                .await?;

            block_miner.abort();

            info!(
                fed_size,
                offline_nodes, "Wallet V2 FROST peg-in and peg-out test successful"
            );

            Ok(())
        })
        .await
}
