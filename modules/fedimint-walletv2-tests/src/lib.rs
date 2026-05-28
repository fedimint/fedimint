//! Shared helpers for the walletv2 devimint test binaries (`bin/*.rs`).
//!
//! These wrap the `fedimint-cli` walletv2 subcommands and the common polling
//! patterns used across the test binaries so they don't have to be duplicated.

use std::time::Duration;

use anyhow::ensure;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use devimint::cmd;
use devimint::external::Bitcoind;
use devimint::federation::Client;
use fedimint_core::runtime::sleep;
use fedimint_core::task::sleep_in_test;
use fedimint_walletv2_common::TxInfo;
use fedimint_walletv2_common::taproot::frost::FrostFinalizationStatsSummary;
use serde::Deserialize;
use tokio::task::JoinHandle;

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum FinalSendState {
    Success(Txid),
    Aborted,
    Failure,
}

/// Spawns a background task that mines a block every 100ms, simulating
/// continuous block production. This prevents deadlocks where the federation's
/// pending bitcoin transactions block further progress because no blocks are
/// being mined to confirm them.
pub fn spawn_block_miner(bitcoind: Bitcoind) -> JoinHandle<()> {
    fedimint_core::runtime::spawn("background-block-miner", async move {
        loop {
            if let Err(e) = bitcoind.mine_blocks(1).await {
                tracing::warn!("Background block miner failed to mine block: {e}");
            }

            sleep(Duration::from_millis(100)).await;
        }
    })
}

/// Returns whether a module of the given `kind` is present in the client's
/// federation.
pub async fn module_is_present(client: &Client, kind: &str) -> anyhow::Result<bool> {
    let modules = cmd!(client, "module").out_json().await?;

    let modules = modules["list"].as_array().expect("module list is an array");

    Ok(modules.iter().any(|m| m["kind"].as_str() == Some(kind)))
}

/// Polls until the walletv2 consensus block count reaches at least
/// `block_count`.
pub async fn await_consensus_block_count(client: &Client, block_count: u64) -> anyhow::Result<()> {
    loop {
        let value = cmd!(client, "module", "walletv2", "info", "block-count")
            .out_json()
            .await?;

        if block_count <= serde_json::from_value(value)? {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for consensus to reach block count {block_count}"),
            Duration::from_secs(1),
        )
        .await;
    }
}

/// Ensures the federation's total walletv2 value is at least `min_value`.
pub async fn ensure_federation_total_value(client: &Client, min_value: u64) -> anyhow::Result<()> {
    let value = cmd!(client, "module", "walletv2", "info", "total-value")
        .out_json()
        .await?;

    ensure!(
        min_value <= serde_json::from_value(value)?,
        "Total federation total value is below {min_value}"
    );

    Ok(())
}

/// Waits until a peg-in to `address` is detected and its claim has reached its
/// final receive state.
pub async fn await_peg_in(client: &Client, address: &Address) -> anyhow::Result<()> {
    cmd!(client, "module", "walletv2", "await-peg-in", address)
        .run()
        .await
}

/// Polls until the federation has no pending bitcoin transactions.
pub async fn await_no_pending_txs(client: &Client) -> anyhow::Result<()> {
    loop {
        let value = cmd!(client, "module", "walletv2", "info", "pending-tx-chain")
            .out_json()
            .await?;

        let pending: Vec<serde_json::Value> = serde_json::from_value(value)?;

        if pending.is_empty() {
            return Ok(());
        }

        sleep_in_test(
            format!(
                "Waiting for {} pending transactions to clear",
                pending.len()
            ),
            Duration::from_secs(1),
        )
        .await;
    }
}

/// Ensures the federation's walletv2 transaction chain has `expected` entries.
pub async fn ensure_tx_chain_length(client: &Client, expected: usize) -> anyhow::Result<()> {
    let value = cmd!(client, "module", "walletv2", "info", "tx-chain")
        .out_json()
        .await?;

    let chain: Vec<serde_json::Value> = serde_json::from_value(value)?;

    ensure!(chain.len() == expected);

    Ok(())
}

/// Requests a fresh walletv2 deposit address from the client.
pub async fn get_deposit_address(client: &Client) -> anyhow::Result<Address> {
    let address = serde_json::from_value::<Address<NetworkUnchecked>>(
        cmd!(client, "module", "walletv2", "receive")
            .out_json()
            .await?,
    )?
    .assume_checked();

    Ok(address)
}

/// Queries every guardian for its FROST finalization stat for `txid` (via the
/// authenticated CLI command) and returns the client-computed median/mean
/// summary. Uses admin auth `--our-id 0 --password pass`; peer 0 is always
/// online in devimint because `degrade_federation` shuts down the
/// highest-indexed guardians first.
pub async fn frost_finalization_stats(
    client: &Client,
    txid: Txid,
) -> anyhow::Result<FrostFinalizationStatsSummary> {
    let value = cmd!(
        client,
        "--our-id",
        "0",
        "--password",
        "pass",
        "module",
        "walletv2",
        "frost-finalization-stats",
        txid.to_string()
    )
    .out_json()
    .await?;

    Ok(serde_json::from_value(value)?)
}

/// Returns the federation's chain of bitcoin transactions, oldest first.
pub async fn tx_chain(client: &Client) -> anyhow::Result<Vec<TxInfo>> {
    let value = cmd!(client, "module", "walletv2", "info", "tx-chain")
        .out_json()
        .await?;

    Ok(serde_json::from_value(value)?)
}

/// Queries every guardian for its FROST finalization stat for `txid`, asserts
/// that all online guardians (`fed_size - offline_nodes`) responded, and logs
/// the median/mean finalization latency plus the (consensus-driven) attempt
/// count under `label`. Call only once the transaction has finalized (e.g.
/// after [`await_no_pending_txs`]).
pub async fn report_frost_finalization_stats(
    client: &Client,
    label: &str,
    txid: Txid,
    fed_size: usize,
    offline_nodes: usize,
) -> anyhow::Result<()> {
    let expected_online = fed_size - offline_nodes;
    let summary = frost_finalization_stats(client, txid).await?;

    ensure!(
        summary.responses == expected_online,
        "Expected FROST finalization stats for {label} from all {expected_online} online \
         guardians, but only {} responded",
        summary.responses,
    );

    tracing::info!(
        label,
        txid = %txid,
        fed_size,
        offline_nodes,
        guardians_reporting = summary.responses,
        attempts = ?summary.attempts,
        median_ms = ?summary.median_duration_millis,
        mean_ms = ?summary.mean_duration_millis,
        "FROST finalization latency"
    );

    Ok(())
}
