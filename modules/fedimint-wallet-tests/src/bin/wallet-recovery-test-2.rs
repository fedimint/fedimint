use devimint::cmd;
use devimint::federation::Client;
use devimint::util::{FedimintCli, FedimintdCmd};
use devimint::version_constants::{VERSION_0_3_0_ALPHA, VERSION_0_4_0};
use fedimint_logging::LOG_TEST;
use futures::try_join;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
