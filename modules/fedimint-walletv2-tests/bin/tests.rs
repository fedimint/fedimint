use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount};
use devimint::federation::Client;
use devimint::version_constants::VERSION_0_5_0_ALPHA;
use devimint::{cmd, util};
use fedimint_core::task::sleep_in_test;
use fedimint_core::util::SafeUrl;
use fedimint_testing::envs::FM_PORT_ESPLORA_ENV;
use fedimint_walletv2_client::{FinalOperationState, UnspentDeposit};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let fedimint_cli_version = util::FedimintCli::version_or_default().await;
            let fedimintd_version = util::FedimintdCmd::version_or_default().await;

            if fedimint_cli_version < *VERSION_0_5_0_ALPHA {
                info!(%fedimint_cli_version, "Version did not support walletv2 module, skipping");
                return Ok(());
            }

            if fedimintd_version < *VERSION_0_5_0_ALPHA {
                info!(%fedimintd_version, "Version did not support walletv2 module, skipping");
                return Ok(());
            }

            let client = dev_fed
                .fed()
                .await?
                .new_joined_client("walletv2-test-send-and-receive-client")
                .await?;

            assert_eq!(
                cmd!(client, "module", "walletv2", "address", "increment")
                    .out_json()
                    .await?
                    .as_u64()
                    .expect("JSON Value is not an integer"),
                0
            );

            assert_eq!(
                cmd!(client, "module", "walletv2", "address", "count")
                    .out_json()
                    .await?
                    .as_u64()
                    .expect("JSON Value is not an integer"),
                1
            );

            let address = serde_json::from_value::<Address<NetworkUnchecked>>(
                cmd!(client, "module", "walletv2", "address", "derive", "0")
                    .out_json()
                    .await?,
            )?
            .assume_checked();

            dev_fed
                .fed()
                .await?
                .send_to_address(address.to_string(), 100_000)
                .await?;

            dev_fed
                .fed()
                .await?
                .send_to_address(address.to_string(), 200_000)
                .await?;

            let esplora = SafeUrl::parse(&format!(
                "http://127.0.0.1:{}",
                std::env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
            ))
            .expect("Failed to parse esplora api");

            await_claimable_deposit_count(&client, &esplora, 2).await?;

            loop {
                if cmd!(client, "module", "walletv2", "receive-fee")
                    .out_json()
                    .await
                    .is_ok()
                {
                    break;
                }

                sleep_in_test(
                    "Waiting for consensus feerate to become available".to_string(),
                    Duration::from_secs(1),
                )
                .await;
            }

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "walletv2",
                    "receive",
                    "0",
                    "--esplora",
                    esplora
                )
                .out_json()
                .await?,
                serde_json::to_value(FinalOperationState::Success)
                    .expect("JSON serialization failed"),
            );

            await_claimable_deposit_count(&client, &esplora, 1).await?;

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "walletv2",
                    "receive",
                    "0",
                    "--esplora",
                    esplora
                )
                .out_json()
                .await?,
                serde_json::to_value(FinalOperationState::Success)
                    .expect("JSON serialization failed"),
            );

            await_claimable_deposit_count(&client, &esplora, 0).await?;

            // This is a temporary fix until we find out why the received balance is not
            // available.
            dev_fed.fed().await?.pegin_client(300_000, &client).await?;

            loop {
                if client.balance().await? >= 280_000 {
                    break;
                }

                sleep_in_test(
                    "Waiting for balance to become available".to_string(),
                    Duration::from_secs(1),
                )
                .await;
            }

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "walletv2",
                    "send",
                    address,
                    Amount::from_sat(250_000)
                )
                .out_json()
                .await?,
                serde_json::to_value(FinalOperationState::Success)
                    .expect("JSON serialization failed"),
            );

            await_deposit_count(&client, &esplora, 1).await?;

            dev_fed.fed().await?.bitcoind.mine_blocks(21).await?;

            await_claimable_deposit_count(&client, &esplora, 1).await?;

            assert_eq!(
                cmd!(
                    client,
                    "module",
                    "walletv2",
                    "receive",
                    "0",
                    "--esplora",
                    esplora,
                    "--fee",
                    Amount::from_sat(200_000)
                )
                .out_json()
                .await?,
                serde_json::to_value(FinalOperationState::Success)
                    .expect("JSON serialization failed"),
            );

            await_claimable_deposit_count(&client, &esplora, 0).await?;

            Ok(())
        })
        .await
}

async fn await_claimable_deposit_count(
    client: &Client,
    esplora: &SafeUrl,
    deposit_count: usize,
) -> anyhow::Result<()> {
    loop {
        let deposits = serde_json::from_value::<Vec<UnspentDeposit>>(
            cmd!(
                client,
                "module",
                "walletv2",
                "address",
                "check",
                "0",
                "--esplora",
                esplora
            )
            .out_json()
            .await?,
        )?;

        if deposits
            .iter()
            .filter(|d| d.confirmations_required == Some(0))
            .count()
            == deposit_count
        {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for {deposit_count} deposits to be claimable"),
            Duration::from_secs(1),
        )
        .await;
    }
}

async fn await_deposit_count(
    client: &Client,
    esplora: &SafeUrl,
    deposit_count: usize,
) -> anyhow::Result<()> {
    loop {
        let deposits = serde_json::from_value::<Vec<UnspentDeposit>>(
            cmd!(
                client,
                "module",
                "walletv2",
                "address",
                "check",
                "0",
                "--esplora",
                esplora
            )
            .out_json()
            .await?,
        )?;

        if deposits.len() == deposit_count {
            return Ok(());
        }

        sleep_in_test(
            format!("Waiting for {deposit_count} deposits"),
            Duration::from_secs(1),
        )
        .await;
    }
}
