use anyhow::ensure;
use clap::Parser;
use devimint::version_constants::VERSION_0_11_0_ALPHA;
use devimint::{cmd, util};
use fedimint_walletv2_tests::{
    FinalSendState, await_consensus_block_count, await_no_pending_txs, await_peg_in,
    ensure_federation_total_value, ensure_tx_chain_length, get_deposit_address, module_is_present,
    spawn_block_miner,
};
use tokio::try_join;
use tracing::info;

#[derive(Parser)]
struct Opts {
    /// Wallet descriptor for walletv2 (`wsh`, `tr`, or `frost`). Defaults to
    /// `wsh` when omitted. Sets `FM_WALLETV2_DESCRIPTOR` for the federation.
    #[arg(long)]
    descriptor: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    // Enable walletv2 module instead of wallet v1
    unsafe { std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "true") };
    if let Some(descriptor) = opts.descriptor.as_deref() {
        unsafe { std::env::set_var("FM_WALLETV2_DESCRIPTOR", descriptor) };
    }
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

            let federation_address_1 = get_deposit_address(&client).await?;

            fed.bitcoind
                .send_to(federation_address_1.to_string(), 100_000)
                .await?;

            await_peg_in(&client, &federation_address_1).await?;

            fed.bitcoind
                .send_to(federation_address_1.to_string(), 200_000)
                .await?;

            await_peg_in(&client, &federation_address_1).await?;

            ensure_federation_total_value(&client, 290_000).await?;

            let federation_address_2 = get_deposit_address(&client).await?;

            assert_ne!(federation_address_1, federation_address_2);

            fed.bitcoind
                .send_to(federation_address_2.to_string(), 300_000)
                .await?;

            await_peg_in(&client, &federation_address_2).await?;

            fed.bitcoind
                .send_to(federation_address_2.to_string(), 400_000)
                .await?;

            await_peg_in(&client, &federation_address_2).await?;

            ensure_federation_total_value(&client, 980_000).await?;

            let federation_address_3 = get_deposit_address(&client).await?;

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

            let circular_address = get_deposit_address(&client_two).await?;

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

            await_peg_in(&client_two, &circular_address).await?;

            await_no_pending_txs(&client).await?;

            ensure_tx_chain_length(&client, 6).await?;

            block_miner.abort();

            info!("Wallet V2 send and receive test successful");

            Ok(())
        })
        .await
}
