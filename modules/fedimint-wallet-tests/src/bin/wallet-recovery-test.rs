use anyhow::bail;
use devimint::cmd;
use devimint::util::{FedimintCli, FedimintdCmd};
use devimint::version_constants::VERSION_0_4_0;
use fedimint_core::util::{backoff_util, retry};
use futures::try_join;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fedimint_cli_version = FedimintCli::version_or_default().await;
        let fedimintd_version = FedimintdCmd::version_or_default().await;
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

            cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                .run()
                .await?;

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

            cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                .run()
                .await?;

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

            cmd!(restored, "module", "wallet", "await-deposit", operation_id)
                .run()
                .await?;

            info!("Client slow: Check if claimed");
            assert_eq!(peg_in_amount_sats * 1000 * 2, restored.balance().await?);
        }

        Ok(())
    })
    .await
}
