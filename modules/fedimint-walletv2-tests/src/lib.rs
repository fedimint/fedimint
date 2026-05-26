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
