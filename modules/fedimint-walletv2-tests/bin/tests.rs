use std::time::Duration;

use anyhow::{Context, bail, ensure};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};
use clap::Parser;
use devimint::external::Bitcoind;
use devimint::federation::Client;
use devimint::version_constants::{
    VERSION_0_11_0_ALPHA, VERSION_0_12_0_ALPHA, VERSION_0_13_0_ALPHA,
};
use devimint::{cmd, util};
use fedimint_core::runtime::{sleep, timeout};
use fedimint_core::task::sleep_in_test;
use fedimint_eventlog::EventLogId;
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
    position: EventLogId,
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
async fn await_receive(client: &Client, position: EventLogId) -> anyhow::Result<EventLogId> {
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
    serde_json::from_value(output[1].clone())
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

async fn get_deposit_address(client: &Client) -> anyhow::Result<(Address, EventLogId)> {
    if util::FedimintCli::version_or_default().await >= *VERSION_0_12_0_ALPHA {
        // Capture the event log position *before* deriving the address so
        // `await_receive` only considers payments received afterwards.
        let position =
            serde_json::from_value(cmd!(client, "dev", "next-event-log-id").out_json().await?)
                .context("dev next-event-log-id should return an event log position")?;

        let address = serde_json::from_value::<Address<NetworkUnchecked>>(
            cmd!(client, "module", "walletv2", "receive")
                .out_json()
                .await?,
        )?
        .assume_checked();

        Ok((address, position))
    } else {
        // Legacy (<= 0.11): `receive` returns the bare address. The position is
        // unused on this path as we fall back to polling the balance.
        let address = serde_json::from_value::<Address<NetworkUnchecked>>(
            cmd!(client, "module", "walletv2", "receive")
                .out_json()
                .await?,
        )?
        .assume_checked();

        Ok((address, EventLogId::LOG_START))
    }
}

/// Reserves a receive address and returns it.
async fn reserve_address(client: &Client) -> anyhow::Result<Address> {
    let reservation = cmd!(client, "module", "walletv2", "reserve-address")
        .out_json()
        .await?;

    Ok(
        serde_json::from_value::<Address<NetworkUnchecked>>(reservation["address"].clone())
            .context("reserve-address should return the reserved address")?
            .assume_checked(),
    )
}

#[derive(Parser)]
enum TestCli {
    SendAndReceive,
    Recovery,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Enable walletv2 module instead of wallet v1
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "true") };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLET", "false") };

    match TestCli::parse() {
        TestCli::SendAndReceive => send_and_receive_test().await,
        TestCli::Recovery => recovery_test().await,
    }
}

async fn send_and_receive_test() -> anyhow::Result<()> {
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

            // `send ... all` was added in 0.13.0-alpha; older CLIs parse the
            // value as a plain amount and reject "all".
            if fedimint_cli_version >= *VERSION_0_13_0_ALPHA {
                info!("Sweep the entire remaining balance onchain...");

                let sweep_address = bitcoind.get_new_address().await?;

                // A sweep can only spend notes that exist when it runs. The
                // aborted send above is refunded by the mint's input state
                // machine, which settles independently of the federation's
                // bitcoin transactions — `await_final_send_operation_state`
                // returns as soon as the send aborts, while the refunded notes
                // are still being reissued. Wait for every in-flight state
                // machine to finish, or that refund lands after the sweep and
                // looks like funds left behind.
                cmd!(client, "dev", "wait-complete").run().await?;

                let pre_sweep_balance = client.balance().await?;

                // Sweeping the whole balance has to leave room for the mint's
                // per-note fees and the wallet module's own output fee on top
                // of the on-chain fee. With base fees enabled (the default) a
                // naive `balance - onchain_fee` is underfunded and note
                // selection rejects the send.
                let value = cmd!(client, "module", "walletv2", "send", sweep_address, "all")
                    .out_json()
                    .await?;

                let FinalSendState::Success(txid) = serde_json::from_value(value)? else {
                    panic!("Sweep send operation failed");
                };

                bitcoind.poll_get_transaction(txid).await?;

                // A sweep cannot always drain to exactly zero — the fee is
                // stepwise in the amount, so a sub-denomination remainder can
                // be left behind — but it must move all but a negligible part
                // of the balance.
                let post_sweep_balance = client.balance().await?;

                ensure!(
                    post_sweep_balance < pre_sweep_balance / 100,
                    "Sweep left {post_sweep_balance} msats of {pre_sweep_balance} msats behind"
                );

                await_no_pending_txs(&client).await?;
            }

            block_miner.abort();

            info!("Wallet V2 send and receive test successful");

            Ok(())
        })
        .await
}

/// A wallet restored from its seed claims a payment that was made, while no
/// client of the wallet was running, to an address the wallet had reserved.
///
/// The restored wallet has no record of the reservations. The payment is made
/// to the second of two reserved addresses, so it is only found by a recovery
/// that looks past the first, which is never paid.
///
/// The federation's mint is the v1 one, which cannot be used while it
/// recovers. The `restore` command therefore finds the payment in a client
/// without a primary module to issue the ecash to, and returns once the
/// recovery is complete with the payment still to be claimed. It is the
/// command after it, which opens the client anew, that can claim it.
async fn recovery_test() -> anyhow::Result<()> {
    unsafe { std::env::set_var("FM_ENABLE_MODULE_MINT", "true") };
    unsafe { std::env::set_var("FM_ENABLE_MODULE_MINTV2", "false") };

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let fedimint_cli_version = util::FedimintCli::version_or_default().await;
            let fedimintd_version = util::FedimintdCmd::version_or_default().await;

            if fedimint_cli_version < *VERSION_0_13_0_ALPHA {
                info!(%fedimint_cli_version, "Version did not support walletv2 recovery, skipping");
                return Ok(());
            }

            if fedimintd_version < *VERSION_0_11_0_ALPHA {
                info!(%fedimintd_version, "Version did not support walletv2 module, skipping");
                return Ok(());
            }

            let fed = dev_fed.fed().await?;

            let original = fed
                .new_joined_client("walletv2-test-recovery-original-client")
                .await?;

            ensure!(
                module_is_present(&original, "walletv2").await?,
                "walletv2 module should be present"
            );

            ensure!(
                module_is_present(&original, "mint").await?,
                "mint module should be present"
            );

            ensure!(
                !module_is_present(&original, "mintv2").await?,
                "mintv2 module should not be present"
            );

            // The original wallet is not run again once the payment is made,
            // as it would claim the payment itself. Its seed is therefore
            // taken first.
            let mnemonic = cmd!(original, "print-secret").out_json().await?["secret"]
                .as_str()
                .context("print-secret should return the secret")?
                .to_owned();

            info!("Reserve two addresses and pay the second one...");

            let unpaid_address = reserve_address(&original).await?;
            let paid_address = reserve_address(&original).await?;

            assert_ne!(unpaid_address, paid_address);

            fed.bitcoind
                .send_to(paid_address.to_string(), 100_000)
                .await?;

            // The federation knows of the payment once it is final.
            fed.finalize_mempool_tx().await?;

            info!("Restore the wallet from its seed...");

            let restored = Client::create("walletv2-test-recovery-restored-client").await?;

            restored
                .restore_federation(fed.invite_code()?, mnemonic)
                .await?;

            info!("Wait for the restored wallet to claim the payment...");

            // The claim takes a few seconds. A payment the restored wallet
            // does not know of is one it would wait for without end.
            timeout(
                Duration::from_secs(120),
                await_receive(&restored, EventLogId::LOG_START),
            )
            .await
            .context("The restored wallet did not claim the payment")??;

            ensure_client_balance(&restored, 90_000).await?;

            // The wallet received once, to the address that was paid, and
            // only after its recovery had completed: the client that
            // recovered could not claim.
            let events = cmd!(restored, "dev", "show-event-log", "--limit", "1000")
                .out_json()
                .await?;

            let events = events
                .as_array()
                .context("show-event-log should return a list of events")?;

            let recovered = events
                .iter()
                .position(|event| {
                    event["kind"] == "module-recovery-completed"
                        && event["payload"]["kind"] == "walletv2"
                })
                .context("The recovery of the wallet should have completed")?;

            let receives = events
                .iter()
                .enumerate()
                .filter(|(_, event)| {
                    event["kind"] == "payment-receive" && event["module_kind"] == "walletv2"
                })
                .collect::<Vec<_>>();

            let [(received, receive)] = receives.as_slice() else {
                bail!("The restored wallet should have received once, got {receives:?}");
            };

            ensure!(
                recovered < *received,
                "The payment should be claimed after the recovery, got {events:?}"
            );

            ensure!(
                receive["payload"]["address"] == paid_address.to_string(),
                "The payment to the second reserved address should be claimed, got {receive}"
            );

            ensure!(
                receive["payload"]["reservation"].is_null(),
                "A restored wallet knows of no reservation, got {receive}"
            );

            info!("Wallet V2 recovery test successful");

            Ok(())
        })
        .await
}
