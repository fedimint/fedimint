use std::str::FromStr;

use anyhow::{Result, bail};
use bitcoin::Transaction;
use bitcoincore_rpc::bitcoin::Txid;
use bitcoincore_rpc::bitcoin::address::Address;
use clap::Parser;
use devimint::cmd;
use devimint::federation::Client;
use devimint::util::{FedimintCli, FedimintdCmd};
use devimint::version_constants::{VERSION_0_3_0_ALPHA, VERSION_0_4_0, VERSION_0_6_0_ALPHA};
use fedimint_core::encoding::Decodable;
use fedimint_core::util::{backoff_util, retry};
use fedimint_logging::LOG_TEST;
use tokio::try_join;
use tracing::{debug, info};

#[derive(Parser, Debug)]
pub enum TestCli {
    Recovery1,
    Recovery2,
    CircularDeposit,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = TestCli::parse();

    match opts {
        TestCli::Recovery1 => wallet_recovery_test_1().await,
        TestCli::Recovery2 => wallet_recovery_test_2().await,
        TestCli::CircularDeposit => circular_deposit_test().await,
    }
}

async fn wallet_recovery_test_1() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = FedimintCli::version_or_default().await;
        let fedimintd_version = FedimintdCmd::version_or_default().await;
        // TODO(support:v0.4): recovery was introduced in v0.4.0
        // see: https://github.com/fedimint/fedimint/pull/5546
        if fedimint_cli_version < *VERSION_0_4_0 || fedimintd_version < *VERSION_0_4_0 {
            info!("Skipping whole test on old fedimint-cli/fedimintd that is missing some irrelevant bolts");
            return Ok(());
        }

        let (fed, _bitcoind) = try_join!(dev_fed.fed(), dev_fed.bitcoind())?;

        let peg_in_amount_sats = 100_000;

            // Start this client early, as we need to test waiting for session to close
        let client_slow = fed
            .new_joined_client("wallet-client-recovery-origin")
            .await?;
        info!("Join and claim");
        fed.pegin_client(peg_in_amount_sats, &client_slow).await?;

        let client_slow_pegin_session_count = client_slow.get_session_count().await?;

        info!("### Test wallet restore without a backup");
        {
            let client = fed
                .new_joined_client("wallet-client-recovery-origin")
                .await?;

            info!("Join, but not claim");
            let operation_id = fed
                .pegin_client_no_wait(peg_in_amount_sats, &client)
                .await?;

            info!("Restore without backup");
            let restored = client
                .new_restored("restored-without-backup", fed.invite_code()?)
                .await?;

            if fedimint_cli_version < *VERSION_0_6_0_ALPHA {
                cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                    .run()
                    .await?;
            } else {
                cmd!(restored, "module", "wallet", "await-deposit", "--operation-id", operation_id)
                    .run()
                    .await?;
            }

            info!("Check if claimed");
            assert_eq!(peg_in_amount_sats * 1000, restored.balance().await?);
        }

        info!("### Test wallet restore with a backup");
        {
            let client = fed
                .new_joined_client("wallet-client-recovery-origin")
                .await?;
            assert_eq!(0, client.balance().await?);

            info!("Join and claim");
            fed.pegin_client(peg_in_amount_sats, &client).await?;

            info!("Make a backup");
            cmd!(client, "backup").run().await?;

            info!("Join more, but not claim");
            let operation_id = fed
                .pegin_client_no_wait(peg_in_amount_sats, &client)
                .await?;

            info!("Restore with backup");
            let restored = client
                .new_restored("restored-with-backup", fed.invite_code()?)
                .await?;

            if fedimint_cli_version < *VERSION_0_6_0_ALPHA {
                cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                    .run()
                    .await?;
            } else {
                cmd!(restored, "module", "wallet", "await-deposit", "--operation-id", operation_id)
                    .run()
                    .await?;
            }

            info!("Check if claimed");
            assert_eq!(peg_in_amount_sats * 1000 * 2, restored.balance().await?);
        }

        info!("### Test wallet restore with a history and no backup");
        {
            let client = client_slow;

            retry("wait for next session", backoff_util::aggressive_backoff(), || async {
                if client_slow_pegin_session_count < client.get_session_count().await? {
                    return Ok(());
                }
                bail!("Session didn't close")
            })
            .await
            .expect("timeouted waiting for session to close");

            let operation_id = fed
                .pegin_client_no_wait(peg_in_amount_sats, &client)
                .await?;

            info!("Client slow: Restore without backup");
            let restored = client
                .new_restored("client-slow-restored-without-backup", fed.invite_code()?)
                .await?;

            if fedimint_cli_version < *VERSION_0_6_0_ALPHA {
                cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                    .run()
                    .await?;
            } else {
                cmd!(restored, "module", "wallet", "await-deposit", "--operation-id", operation_id)
                    .run()
                    .await?;
            }

            info!("Client slow: Check if claimed");
            assert_eq!(peg_in_amount_sats * 1000 * 2, restored.balance().await?);
        }

        Ok(())
    })
    .await
}

async fn wallet_recovery_test_2() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = FedimintCli::version_or_default().await;
        let fedimintd_version = FedimintdCmd::version_or_default().await;
        // TODO(support:v0.4): recovery was introduced in v0.4.0
        // see: https://github.com/fedimint/fedimint/pull/5546
        if fedimint_cli_version < *VERSION_0_4_0 || fedimintd_version < *VERSION_0_4_0 {
            info!(target: LOG_TEST, "Skipping whole test on old fedimint-cli/fedimintd that is missing some irrelevant bolts");
            return Ok(());
        }

        let (fed, _bitcoind) = try_join!(dev_fed.fed(), dev_fed.bitcoind())?;

        let peg_in_amount_sats = 100_000;

            // Start this client early, as we need to test waiting for session to close
        let reference_client = fed
            .new_joined_client("wallet-client-recovery-origin")
            .await?;
        info!(target: LOG_TEST, "Join and claim");
        fed.pegin_client(peg_in_amount_sats, &reference_client).await?;


        let secret = cmd!(reference_client, "print-secret").out_json().await?["secret"]
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap();

        let pre_notes = cmd!(reference_client, "info").out_json().await?;

        let pre_balance = pre_notes["total_amount_msat"].as_u64().unwrap();

        debug!(target: LOG_TEST, %pre_notes, pre_balance, "State before backup");

        // we need to have some funds
        // TODO: right now we rely on previous tests to leave some balance
        assert!(0 < pre_balance);

        // without existing backup
        // TODO: Change this test and make them exercise more scenarios.
        // Currently (and probably indefinitely) we can support only one
        // restoration per client state (datadir), as it only makes sense to do
        // once (at the very beginning) and we used a fixed operation id for it.
        // Testing restore in different setups would require multiple clients,
        // which is a larger refactor.
        {
            let post_balance = if fedimint_cli_version >= *VERSION_0_3_0_ALPHA {
                let client = Client::create("restore-without-backup").await?;
                let _ = cmd!(
                    client,
                    "restore",
                    "--mnemonic",
                    &secret,
                    "--invite-code",
                    fed.invite_code()?
                )
                .out_json()
                .await?;

                // `wait-complete` was introduced in v0.3.0 (90f3082)
                let _ = cmd!(client, "dev", "wait-complete").out_json().await?;
                let post_notes = cmd!(client, "info").out_json().await?;
                let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
                debug!(target: LOG_TEST, %post_notes, post_balance, "State after backup");

                post_balance
            } else {
                let client = reference_client
                    .new_forked("restore-without-backup")
                    .await?;
                let _ = cmd!(client, "wipe", "--force",).out_json().await?;

                assert_eq!(
                    0,
                    cmd!(client, "info").out_json().await?["total_amount_msat"]
                        .as_u64()
                        .unwrap()
                );

                let post_balance = cmd!(client, "restore", &secret,)
                    .out_json()
                    .await?
                    .as_u64()
                    .unwrap();
                let post_notes = cmd!(client, "info").out_json().await?;
                debug!(target: LOG_TEST, %post_notes, post_balance, "State after backup");

                post_balance
            };
            assert_eq!(pre_balance, post_balance);
        }

        // with a backup
        {
            if fedimint_cli_version >= *VERSION_0_3_0_ALPHA {
                let _ = cmd!(reference_client, "backup",).out_json().await?;
                let client = Client::create("restore-with-backup").await?;

                {
                    let _ = cmd!(
                        client,
                        "restore",
                        "--mnemonic",
                        &secret,
                        "--invite-code",
                        fed.invite_code()?
                    )
                    .out_json()
                    .await?;

                    let _ = cmd!(client, "dev", "wait-complete").out_json().await?;
                    let post_notes = cmd!(client, "info").out_json().await?;
                    let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
                    debug!(target: LOG_TEST, %post_notes, post_balance, "State after backup");

                    assert_eq!(pre_balance, post_balance);
                }

                // Now make a backup using the just restored client, and confirm restoring again
                // still works (no corruption was introduced)
                let _ = cmd!(client, "backup",).out_json().await?;

                const EXTRA_PEGIN_SATS: u64 = 1000;
                fed.pegin_client(EXTRA_PEGIN_SATS, &client).await?;

                {
                    let client = Client::create("restore-with-backup-again").await?;
                    let _ = cmd!(
                        client,
                        "restore",
                        "--mnemonic",
                        &secret,
                        "--invite-code",
                        fed.invite_code()?
                    )
                    .out_json()
                    .await?;

                    let _ = cmd!(client, "dev", "wait-complete").out_json().await?;
                    let post_notes = cmd!(client, "info").out_json().await?;
                    let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
                    debug!(target: LOG_TEST, %post_notes, post_balance, "State after (subsequent) backup");

                    assert_eq!(pre_balance + EXTRA_PEGIN_SATS * 1000, post_balance);
                }
            } else {
                let client = reference_client.new_forked("restore-with-backup").await?;
                let _ = cmd!(client, "backup",).out_json().await?;
                let _ = cmd!(client, "wipe", "--force",).out_json().await?;
                assert_eq!(
                    0,
                    cmd!(client, "info").out_json().await?["total_amount_msat"]
                        .as_u64()
                        .unwrap()
                );
                let _ = cmd!(client, "restore", &secret,).out_json().await?;
                let post_notes = cmd!(client, "info").out_json().await?;
                let post_balance = post_notes["total_amount_msat"].as_u64().unwrap();
                debug!(target: LOG_TEST, %post_notes, post_balance, "State after backup");

                assert_eq!(pre_balance, post_balance);
            }
        }

        Ok(())
    })
    .await
}
async fn assert_withdrawal(
    send_client: &Client,
    receive_client: &Client,
    bitcoind: &devimint::external::Bitcoind,
    fed: &devimint::federation::Federation,
) -> Result<()> {
    let withdrawal_amount_sats = 50_000;
    let withdrawal_amount_msats = withdrawal_amount_sats * 1000;

    if send_client.balance().await? < withdrawal_amount_msats {
        fed.pegin_client(withdrawal_amount_sats * 2, send_client)
            .await?;
    }

    let send_client_pre_balance = send_client.balance().await?;
    let receive_client_pre_balance = receive_client.balance().await?;

    let (deposit_address, operation_id) = receive_client.get_deposit_addr().await?;
    let withdraw_res = cmd!(
        send_client,
        "withdraw",
        "--address",
        &deposit_address,
        "--amount",
        "{withdrawal_amount_sats} sat"
    )
    .out_json()
    .await?;

    // Verify federation broadcasts withdrawal tx
    let txid: Txid = withdraw_res["txid"].as_str().unwrap().parse().unwrap();
    let tx_hex = bitcoind.poll_get_transaction(txid).await?;

    let parsed_address = Address::from_str(&deposit_address)?;
    let tx = Transaction::consensus_decode_hex(&tx_hex, &Default::default())?;
    assert!(tx.output.iter().any(|o| o.script_pubkey
        == parsed_address.clone().assume_checked().script_pubkey()
        && o.value.to_sat() == withdrawal_amount_sats));

    // Verify the receive client gets the deposit
    try_join!(
        bitcoind.mine_blocks(21),
        receive_client.await_deposit(&operation_id),
    )?;

    // Balance checks
    let send_client_post_balance = send_client.balance().await?;
    let receive_client_post_balance = receive_client.balance().await?;
    let fed_deposit_fees_msats = fed.deposit_fees()?.msats;
    let onchain_fees_msats = withdraw_res["fees_sat"].as_u64().unwrap() * 1000;

    let expected_send_client_balance = if send_client.get_name() == receive_client.get_name() {
        send_client_pre_balance - onchain_fees_msats - fed_deposit_fees_msats
    } else {
        send_client_pre_balance - withdrawal_amount_msats - onchain_fees_msats
    };

    let expected_receive_client_balance = if send_client.get_name() == receive_client.get_name() {
        receive_client_pre_balance - onchain_fees_msats - fed_deposit_fees_msats
    } else {
        receive_client_pre_balance + withdrawal_amount_msats - fed_deposit_fees_msats
    };

    assert_eq!(send_client_post_balance, expected_send_client_balance);
    assert_eq!(receive_client_post_balance, expected_receive_client_balance);

    Ok(())
}

async fn circular_deposit_test() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let (fed, bitcoind) = try_join!(dev_fed.fed(), dev_fed.bitcoind())?;

        let send_client = fed
            .new_joined_client("circular-deposit-send-client")
            .await?;

        // Verify withdrawal to deposit address from same client
        assert_withdrawal(&send_client, &send_client, bitcoind, fed).await?;

        // Verify withdrawal to deposit address from different client in same federation
        let receive_client = fed
            .new_joined_client("circular-deposit-receive-client")
            .await?;
        assert_withdrawal(&send_client, &receive_client, bitcoind, fed).await?;

        Ok(())
    })
    .await
}
