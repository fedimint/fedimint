use anyhow::Result;
use devimint::cmd;
use devimint::federation::Federation;
use devimint::util::FedimintCli;
use devimint::version_constants::VERSION_0_5_0_ALPHA;
use fedimint_logging::LOG_DEVIMINT;
use rand::Rng;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|fed, _process_mgr| async move {
        let fed = fed.fed().await?;

        test_restore_gap_test(fed).await?;
        Ok(())
    })
    .await
}

pub async fn test_restore_gap_test(fed: &Federation) -> Result<()> {
    let client = fed.new_joined_client("restore-gap-test").await?;
    let fedimint_cli_version = FedimintCli::version_or_default().await;

    if fedimint_cli_version < *VERSION_0_5_0_ALPHA {
        return Ok(());
    }

    const PEGIN_SATS: u64 = 300000;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    for i in 0..20 {
        let reissure_amount_sats = if i % 2 == 0 {
            // half of the time, reissue everything
            PEGIN_SATS
        } else {
            // other half, random amount
            rand::thread_rng().gen_range(10..PEGIN_SATS)
        };
        debug!(target: LOG_DEVIMINT, i, reissure_amount_sats, "Reissue");

        let notes = cmd!(client, "spend", reissure_amount_sats * 1000)
            .out_json()
            .await?
            .get("notes")
            .expect("Output didn't contain e-cash notes")
            .as_str()
            .unwrap()
            .to_owned();

        // Test we can reissue our own notes
        cmd!(client, "reissue", notes).out_json().await?;
    }

    let secret = cmd!(client, "print-secret").out_json().await?["secret"]
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap();

    let pre_notes = cmd!(client, "info").out_json().await?;

    let pre_balance = pre_notes["total_amount_msat"].as_u64().unwrap();

    info!(target: LOG_DEVIMINT, %pre_notes, pre_balance, "State before backup");

    // we need to have some funds
    assert!(0 < pre_balance);

    // without existing backup
    {
        let client = devimint::federation::Client::create("restore-gap-test-without-backup")?;
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
        info!(target: LOG_DEVIMINT, %post_notes, post_balance, "State after backup");
        assert_eq!(pre_balance, post_balance);
        assert_eq!(pre_notes, post_notes);
    }

    Ok(())
}
