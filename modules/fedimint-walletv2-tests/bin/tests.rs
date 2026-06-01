use std::time::Duration;

use anyhow::{Context, ensure};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use devimint::external::Bitcoind;
use devimint::federation::Client;
use devimint::version_constants::{VERSION_0_11_0_ALPHA, VERSION_0_12_0_ALPHA};
use devimint::{cmd, util};
use fedimint_core::runtime::sleep;
use fedimint_core::task::sleep_in_test;
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio::try_join;
use tracing::info;

/// Spawns a background task that mines a block every 100ms, simulating
/// continuous block production. This prevents deadlocks where the federation's
/// pending bitcoin transactions block further progress because no blocks are
/// being mined to confirm them.
fn spawn_block_miner(bitcoind: Bitcoind) -> JoinHandle<()> {
    fedimint_core::runtime::spawn("background-block-miner", async move {
        loop {
            if let Err(e) = bitcoind.mine_blocks(1).await {
                tracing::warn!("Background block miner failed to mine block: {e}");
            }

            sleep(Duration::from_millis(100)).await;
        }
    })
}

async fn module_is_present(client: &Client, kind: &str) -> anyhow::Result<bool> {
    let modules = cmd!(client, "module").out_json().await?;

    let modules = modules["list"].as_array().expect("module list is an array");

    Ok(modules.iter().any(|m| m["kind"].as_str() == Some(kind)))
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum FinalSendState {
    Success(Txid),
    Aborted,
    Failure,
}

async fn await_consensus_block_count(client: &Client, block_count: u64) -> anyhow::Result<()> {
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

async fn ensure_federation_total_value(client: &Client, min_value: u64) -> anyhow::Result<()> {
    let value = cmd!(client, "module", "walletv2", "info", "total-value")
        .out_json()
        .await?;

    ensure!(
        min_value <= serde_json::from_value(value)?,
        "Total federation total value is below {min_value}"
    );

    Ok(())
}

/// Waits for `receives` deposits to be claimed (starting from event log
/// `position`) and then asserts the client balance reached at least
/// `min_balance` sats.
///
/// On `fedimint-cli` versions without `await-receive` (<= 0.11), falls back to
/// polling the balance like the test used to.
async fn await_deposits(
    client: &Client,
    position: u64,
    receives: usize,
    min_balance: u64,
) -> anyhow::Result<()> {
    if util::FedimintCli::version_or_default().await >= *VERSION_0_12_0_ALPHA {
        let mut position = position;

        for _ in 0..receives {
            position = await_receive(client, position).await?;
        }

        ensure_client_balance(client, min_balance).await?;
    } else {
        await_client_balance(client, min_balance).await?;
    }

    Ok(())
}

/// Waits for the next receive recorded at or after `position` to be claimed,
/// returning the event log position to use for the following wait.
async fn await_receive(client: &Client, position: u64) -> anyhow::Result<u64> {
    let output = cmd!(
        client,
        "module",
        "walletv2",
        "await-receive",
        position.to_string()
    )
    .out_json()
    .await?;

    // Walletv2 `await-receive` returns `[final_state, next_position]`.
    output[1]
        .as_u64()
        .context("await-receive should return the next event log position")
}

/// Asserts the client balance has reached at least `min_balance` sats.
async fn ensure_client_balance(client: &Client, min_balance: u64) -> anyhow::Result<()> {
    let balance = client.balance().await?;

    // Client balance is in msats, min_balance is in sats.
    ensure!(
        balance >= min_balance * 1000,
        "Client balance {balance} is below {min_balance}"
    );

    Ok(())
}

/// Legacy fallback for `fedimint-cli` <= 0.11: polls the client balance until
/// it reaches at least `min_balance` sats.
async fn await_client_balance(client: &Client, min_balance: u64) -> anyhow::Result<()> {
    loop {
        cmd!(client, "dev", "wait", "3").out_json().await?;

        let balance = client.balance().await?;

        // Client balance is in msats, min_balance is in sats.
        if balance >= min_balance * 1000 {
            return Ok(());
        }

        info!("Waiting for client balance {balance} to reach {min_balance}");
    }
}

async fn await_no_pending_txs(client: &Client) -> anyhow::Result<()> {
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

async fn ensure_tx_chain_length(client: &Client, expected: usize) -> anyhow::Result<()> {
    let value = cmd!(client, "module", "walletv2", "info", "tx-chain")
        .out_json()
        .await?;

    let chain: Vec<serde_json::Value> = serde_json::from_value(value)?;

    ensure!(chain.len() == expected,);

    Ok(())
}

async fn get_deposit_address(client: &Client) -> anyhow::Result<(Address, u64)> {
    let output = cmd!(client, "module", "walletv2", "receive")
        .out_json()
        .await?;

    if util::FedimintCli::version_or_default().await >= *VERSION_0_12_0_ALPHA {
        // Walletv2 `receive` returns `[address, event_log_position]`.
        let address = serde_json::from_value::<Address<NetworkUnchecked>>(output[0].clone())?
            .assume_checked();

        let position = output[1]
            .as_u64()
            .context("receive should return an event log position")?;

        Ok((address, position))
    } else {
        // Legacy (<= 0.11): `receive` returns the bare address. The position is
        // unused on this path as we fall back to polling the balance.
        let address = serde_json::from_value::<Address<NetworkUnchecked>>(output)?.assume_checked();

        Ok((address, 0))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Enable walletv2 module instead of wallet v1
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "true") };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLET", "false") };

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
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

            let client = fed
                .new_joined_client("walletv2-test-send-and-receive-client")
                .await?;

            info!("Verify that walletv1 is not present...");

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

            // We need the consensus block count to reach a non-zero value before we send
            // in any funds such that the UTXO is tracked by the federation.

            info!("Wait for the consensus to reach block count one");

            await_consensus_block_count(&client, 1).await?;

            info!("Deposit funds into the federation...");

            let (federation_address_1, position) = get_deposit_address(&client).await?;

            fed.bitcoind
                .send_to(federation_address_1.to_string(), 100_000)
                .await?;

            fed.bitcoind
                .send_to(federation_address_1.to_string(), 200_000)
                .await?;

            info!("Wait for deposits to be claimed...");

            // Two UTXOs were sent to the same address; wait for both receives.
            await_deposits(&client, position, 2, 290_000).await?;

            ensure_federation_total_value(&client, 290_000).await?;

            let (federation_address_2, position) = get_deposit_address(&client).await?;

            assert_ne!(federation_address_1, federation_address_2);

            fed.bitcoind
                .send_to(federation_address_2.to_string(), 300_000)
                .await?;

            fed.bitcoind
                .send_to(federation_address_2.to_string(), 400_000)
                .await?;

            info!("Wait for deposits to be claimed...");

            await_deposits(&client, position, 2, 980_000).await?;

            ensure_federation_total_value(&client, 980_000).await?;

            let (federation_address_3, _) = get_deposit_address(&client).await?;

            assert_ne!(federation_address_2, federation_address_3);

            info!("Send funds back onchain...");

            let withdraw_address = bitcoind.get_new_address().await?;

            let value = cmd!(
                client,
                "module",
                "walletv2",
                "send",
                withdraw_address,
                "500000 sat"
            )
            .out_json()
            .await?;

            let FinalSendState::Success(txid) = serde_json::from_value(value)? else {
                panic!("Send operation failed");
            };

            bitcoind.poll_get_transaction(txid).await?;

            let total_value: u64 = serde_json::from_value(
                cmd!(client, "module", "walletv2", "info", "total-value")
                    .out_json()
                    .await?,
            )?;

            assert!(
                total_value < 500_000,
                "Federation total value should be less than 500_000 sats"
            );

            await_no_pending_txs(&client).await?;

            ensure_tx_chain_length(&client, 4).await?;

            info!("Verify that a send with zero fee aborts...");

            let abort_address = bitcoind.get_new_address().await?;

            let value = cmd!(
                client,
                "module",
                "walletv2",
                "send",
                abort_address,
                "100000 sat",
                "--fee",
                "0 sat"
            )
            .out_json()
            .await?;

            assert_eq!(
                FinalSendState::Aborted,
                serde_json::from_value(value)?,
                "Send with zero fee should abort"
            );

            info!("Test circular deposit (send to second client's federation address)...");

            let client_two = fed
                .new_joined_client("walletv2-test-circular-deposit-client")
                .await?;

            let (circular_address, position) = get_deposit_address(&client_two).await?;

            let value = cmd!(
                client,
                "module",
                "walletv2",
                "send",
                circular_address.to_string(),
                "100000 sat"
            )
            .out_json()
            .await?;

            let FinalSendState::Success(txid) = serde_json::from_value(value)? else {
                panic!("Circular deposit send operation failed");
            };

            bitcoind.poll_get_transaction(txid).await?;

            await_deposits(&client_two, position, 1, 99_000).await?;

            await_no_pending_txs(&client).await?;

            ensure_tx_chain_length(&client, 6).await?;

            block_miner.abort();

            info!("Wallet V2 send and receive test successful");

            Ok(())
        })
        .await
}
