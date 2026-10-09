use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow, ensure};
use clap::Parser;
use devimint::federation::Federation;
use devimint::util::{ProcessManager, poll};
use devimint::version_constants::VERSION_0_13_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::NumPeers;
use fedimint_core::setup_code::WalletDescriptorKind;
use fedimint_walletv2_tests::{
    FinalSendState, await_consensus_block_count, await_no_pending_txs, await_receive,
    ensure_address_matches_descriptor, ensure_federation_total_value, get_deposit_address,
    module_is_present, report_frost_finalization_stats, spawn_block_miner, tx_chain,
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

    /// Wipe one guardian's database before the FROST-signed transactions, so
    /// it rejoins with replicated signing commitments it no longer holds the
    /// nonces for, and assert the federation still signs once the offline
    /// guardians are taken down as well.
    #[arg(long)]
    nonce_loss: bool,
}

/// The guardian whose database the `--nonce-loss` scenario wipes. Peer `0`
/// is left alone, and `degrade_federation` takes the highest peer ids
/// offline, so peer `1` is online in every combination this test runs.
const NONCE_LOSS_PEER: usize = 1;

/// How long the `--nonce-loss` scenario may take from the wipe until a
/// FROST-signed transaction completes.
///
/// Every guardian runs with a nonce buffer of 2, so the pool holds exactly 4
/// unusable commitments: the wiped guardian's 2 and the offline guardian's 2.
/// A signing attempt only fails if it draws one of them, and drawing one
/// consumes it, so at most 4 attempts fail before one succeeds. Each failed
/// attempt costs `LOCAL_ADVANCE_TIMEOUT` (30s), which bounds signing at about
/// 2 minutes.
const NONCE_LOSS_TIMEOUT: Duration = Duration::from_mins(4);

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

        return run_single_federation(fed_size, offline_nodes, opts.nonce_loss).await;
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

    run_driver(&opts.fed_sizes, opts.nonce_loss).await
}

/// Re-invokes this binary once per `(fed_size, offline_nodes)` combination,
/// covering every offline level from `0` up to `max_evil()` for each federation
/// size. Fails on the first combination whose worker process exits non-zero.
async fn run_driver(fed_sizes: &[usize], nonce_loss: bool) -> anyhow::Result<()> {
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

            let mut worker = tokio::process::Command::new(&current_exe);
            worker
                .arg("--fed-size")
                .arg(fed_size.to_string())
                .arg("--offline-nodes")
                .arg(offline_nodes.to_string())
                .env("FM_TEST_DIR", &test_dir);
            if nonce_loss {
                worker.arg("--nonce-loss");
            }

            let status = worker.status().await.with_context(|| {
                format!("spawning worker for fed_size={fed_size}, offline_nodes={offline_nodes}")
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
/// guardians with `offline_nodes` of them taken offline. With `nonce_loss`,
/// [`NONCE_LOSS_PEER`] loses its database between the first deposit and the
/// first FROST-signed transaction, and the offline guardians are only taken
/// down after it has caught up (see [`lose_nonces_then_degrade`]).
async fn run_single_federation(
    fed_size: usize,
    offline_nodes: usize,
    nonce_loss: bool,
) -> anyhow::Result<()> {
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
    let startup_offline_nodes = if nonce_loss { 0 } else { offline_nodes };
    unsafe { std::env::set_var("FM_OFFLINE_NODES", startup_offline_nodes.to_string()) };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "true") };
    unsafe { std::env::set_var("FM_WALLETV2_DESCRIPTOR", "frost") };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLET", "false") };
    // The nonce-loss scenario uses the minimum buffer to bound the number of
    // unusable commitments (see `NONCE_LOSS_TIMEOUT`).
    let nonce_buffer_target = if nonce_loss { "2" } else { "3" };
    unsafe { std::env::set_var("FM_WALLETV2_FROST_NONCE_BUFFER_TARGET", nonce_buffer_target) };

    devimint::run_devfed_test()
        .call(move |dev_fed, process_mgr| async move {
            info!(
                fed_size,
                offline_nodes, nonce_loss, "Starting FROST federation test"
            );

            let fedimint_cli_version = util::FedimintCli::version_or_default().await;
            let fedimintd_version = util::FedimintdCmd::version_or_default().await;

            // The FROST wallet descriptor, the ROAST signing session and the
            // `frost_finalization_stats` admin endpoint all landed in
            // 0.13.0-alpha. Older binaries ignore `FM_WALLETV2_DESCRIPTOR` and
            // silently run a non-FROST walletv2 wallet, so there is nothing
            // meaningful to assert against them.
            if fedimint_cli_version < *VERSION_0_13_0_ALPHA {
                info!(%fedimint_cli_version, "Version did not support the FROST wallet, skipping");
                return Ok(());
            }

            if fedimintd_version < *VERSION_0_13_0_ALPHA {
                info!(%fedimintd_version, "Version did not support the FROST wallet, skipping");
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

            // A guardian that ignored `FM_WALLETV2_DESCRIPTOR` would build a
            // `wsh` wallet, making every FROST assertion below vacuous.
            ensure_address_matches_descriptor(&seed_address, WalletDescriptorKind::Frost)?;

            bitcoind.send_to(seed_address.to_string(), 100_000).await?;

            await_receive(&client, seed_position).await?;

            // No FROST-signed transaction has run yet, so every commitment the
            // guardian published is still in the replicated pool and none of
            // them can be signed with once its database is gone.
            //
            // The restarted guardian's process handle lives in the returned
            // clone and terminates the process when dropped, so keep it alive.
            let _degraded_fed = if nonce_loss {
                let fed = tokio::time::timeout(NONCE_LOSS_TIMEOUT, async {
                    let fed =
                        lose_nonces_then_degrade(fed, &client, &process_mgr, offline_nodes).await?;
                    consolidate(&client, bitcoind).await?;
                    anyhow::Ok(fed)
                })
                .await
                .context("FROST signing stalled after a guardian lost its nonces")??;
                Some(fed)
            } else {
                consolidate(&client, bitcoind).await?;
                None
            };

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
            await_signed(&client, nonce_loss).await?;

            report_frost_finalization_stats(&client, "peg-out", txid, fed_size, offline_nodes)
                .await?;

            block_miner.abort();

            info!(
                fed_size,
                offline_nodes, nonce_loss, "Wallet V2 FROST peg-in and peg-out test successful"
            );

            Ok(())
        })
        .await
}

/// Deposits into the non-empty wallet, which sweeps the existing UTXO and the
/// new deposit into a single FROST-signed consolidation transaction, and waits
/// until it is signed.
async fn consolidate(
    client: &devimint::federation::Client,
    bitcoind: &devimint::external::Bitcoind,
) -> anyhow::Result<()> {
    info!("Deposit again to trigger a FROST-signed consolidation tx...");

    let (consolidation_address, consolidation_position) = get_deposit_address(client).await?;

    bitcoind
        .send_to(consolidation_address.to_string(), 100_000)
        .await?;

    await_receive(client, consolidation_position).await?;

    ensure_federation_total_value(client, 180_000).await?;

    // Once there are no pending transactions, the consolidation tx has
    // finalized and every online guardian has deterministically recorded
    // its FROST finalization stat.
    await_no_pending_txs(client).await
}

/// Restarts [`NONCE_LOSS_PEER`] with an empty database, as after a disk loss
/// or a restore that only kept its config, then takes the highest
/// `offline_nodes` guardians offline. Returns the federation handle that owns
/// the restarted guardian's process.
///
/// The guardian replays consensus history from the other guardians, which puts
/// back its old signing commitments, but the nonces behind them were never
/// part of consensus and are gone for good. It generates fresh nonces on
/// startup, since it only counts the ones in its own database.
///
/// AlephBFT keeps a guardian's messages for the open session in its database,
/// so the wiped guardian contradicts itself in the session it was stopped in.
/// That session needs every other guardian to complete, so the offline
/// guardians only go down once the wiped guardian has completed it.
async fn lose_nonces_then_degrade(
    fed: &Federation,
    client: &devimint::federation::Client,
    process_mgr: &ProcessManager,
    offline_nodes: usize,
) -> anyhow::Result<Federation> {
    let mut fed = fed.clone();
    let peer = NONCE_LOSS_PEER;

    info!(peer, "Wiping guardian database to lose its FROST nonces");

    // `fedimint_server::config::io::DB_FILE`
    let db_dir = fed
        .vars
        .get(&peer)
        .context("nonce-loss peer has no env vars")?
        .FM_DATA_DIR
        .join("database");

    fed.terminate_server(peer).await?;

    // The session the guardian was stopped in can't be past the one the
    // others are in now.
    let open_session = peer_session_count(client, 0).await?;

    tokio::fs::remove_dir_all(&db_dir)
        .await
        .with_context(|| format!("removing {}", db_dir.display()))?;

    fed.start_server(process_mgr, peer).await?;

    poll(
        "Wiped guardian completes the session it was stopped in",
        || async {
            let session_count = peer_session_count(client, peer)
                .await
                .map_err(ControlFlow::Continue)?;

            if session_count <= open_session {
                return Err(ControlFlow::Continue(anyhow!(
                    "guardian {peer} has completed {session_count} sessions, waiting for {}",
                    open_session + 1
                )));
            }

            Ok(())
        },
    )
    .await?;

    let fed_size = fed.vars.len();
    for offline_peer in (fed_size - offline_nodes)..fed_size {
        fed.terminate_server(offline_peer).await?;
    }

    if offline_nodes > 0 {
        info!(fed_size, offline_nodes, "federation is degraded");
    }

    Ok(fed)
}

/// Returns the number of consensus sessions `peer` has completed.
async fn peer_session_count(
    client: &devimint::federation::Client,
    peer: usize,
) -> anyhow::Result<u64> {
    cmd!(client, "dev", "api", "--peer-id", peer, "session_count")
        .out_json()
        .await?["value"]
        .as_u64()
        .context("session count wasn't a number")
}

/// Waits until the federation has no pending transactions. In the nonce-loss
/// scenario a stalled signing would otherwise hang the test forever, so it
/// fails after [`NONCE_LOSS_TIMEOUT`] instead.
async fn await_signed(
    client: &devimint::federation::Client,
    nonce_loss: bool,
) -> anyhow::Result<()> {
    if !nonce_loss {
        return await_no_pending_txs(client).await;
    }

    tokio::time::timeout(NONCE_LOSS_TIMEOUT, await_no_pending_txs(client))
        .await
        .context("FROST signing stalled after a guardian lost its nonces")?
}
