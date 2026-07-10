use anyhow::Result;
use clap::Parser;
use devimint::cmd;
use devimint::federation::{Client, Federation};
use devimint::util::{FedimintCli, almost_equal};
use devimint::version_constants::VERSION_0_12_0_ALPHA;
use fedimint_client_module::ModuleRecoveryCompleted;
use fedimint_logging::LOG_DEVIMINT;
use rand::Rng;
use tokio::try_join;
use tracing::info;

#[derive(Debug, Parser)]
enum Cmd {
    Restore,
    /// Mint recovery test. Run with `FM_FORCE_V1_MINT_RECOVERY=1` to force
    /// V1 (session-based) recovery path.
    RecoveryV1,
    /// Mint recovery test using default (V2 slice-based) recovery path.
    RecoveryV2,
    Sanity,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cmd::parse() {
        Cmd::Restore => restore().await,
        Cmd::RecoveryV1 => mint_recovery_test().await,
        Cmd::RecoveryV2 => mint_recovery_test().await,
        Cmd::Sanity => sanity().await,
    }
}

async fn restore() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|fed, _process_mgr| async move {
            let fed = fed.fed().await?;

            test_restore_gap_test(fed).await?;
            Ok(())
        })
        .await
}

pub async fn test_restore_gap_test(fed: &Federation) -> Result<()> {
    let client = fed.new_joined_client("restore-gap-test").await?;
    const PEGIN_SATS: u64 = 300000;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    for i in 0..20 {
        let gap = rand::thread_rng().gen_range(0..20);
        info!(target: LOG_DEVIMINT, gap, "Gap");
        cmd!(
            client,
            "dev",
            "advance-note-idx",
            "--amount",
            "1024msat",
            "--count",
            // we are not guaranteed to use a 1024 note on every payment,
            // so create some random small gaps, so it's very unlikely we
            // would cross the default gap limit accidentally
            &gap.to_string()
        )
        .run()
        .await?;

        // We need to get the balance of the client to know how much to reissue, due to
        // the mint base fees it decreases slightly every time we reissue.
        let notes = cmd!(client, "info").out_json().await?;
        let balance = notes["total_amount_msat"].as_u64().unwrap();

        let reissure_amount = if i % 2 == 0 {
            // half of the time, reissue everything
            balance
        } else {
            // other half, random amount
            rand::thread_rng().gen_range(10..(balance))
        };
        info!(target: LOG_DEVIMINT, i, reissure_amount, "Reissue");

        let notes = cmd!(client, "spend", reissure_amount)
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
        let client =
            devimint::federation::Client::create("restore-gap-test-without-backup").await?;
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
        info!(target: LOG_DEVIMINT, %post_notes, post_balance, "State after backup");
        assert_eq!(pre_balance, post_balance);
        assert_eq!(pre_notes, post_notes);
    }

    Ok(())
}

/// Test that mint recovery works correctly in various scenarios.
///
/// The V1 variant should be run with `FM_FORCE_V1_MINT_RECOVERY=1` to
/// force the legacy session-based recovery path which reissues recovered
/// ecash.
///
/// Regression test for <https://github.com/fedimint/fedimint/issues/8004>
async fn mint_recovery_test() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let fed = dev_fed.fed().await?;

            try_join!(
                test_recovery_with_backup(fed),
                test_recovery_without_backup(fed),
                test_recovery_after_activity(fed),
                test_recovery_with_post_backup_activity(fed),
            )?;

            Ok(())
        })
        .await
}

const PEGIN_SATS: u64 = 1_000_000;

/// Find the mint module's `ModuleRecoveryCompleted` event in a
/// `dev show-event-log` JSON dump.
///
/// Recovery runs for every module, so the mint is matched via the event's
/// `kind`. Only `ModuleRecoveryCompleted` payloads carry a `kind`, so other
/// events deserialize with `kind == None` and are filtered out.
fn mint_recovery_completed(event_log: &serde_json::Value) -> Option<ModuleRecoveryCompleted> {
    event_log.as_array()?.iter().find_map(|entry| {
        let payload = entry.get("payload")?;

        // `show-event-log` renders the payload as its JSON object, or (on older
        // clients) as hex-encoded JSON bytes.
        let event: ModuleRecoveryCompleted = match payload.as_str() {
            Some(hex) => serde_json::from_slice(&hex::decode(hex).ok()?).ok()?,
            None => serde_json::from_value(payload.clone()).ok()?,
        };

        (event.kind.as_ref() == Some(&fedimint_mint_common::KIND)).then_some(event)
    })
}

/// Assert the mint module's recovery-completed event reports the amount that
/// was recovered.
///
/// Version-gated: clients older than 0.12 emit this event without the `amount`
/// field (and lack the `dev show-event-log` command), so the check is skipped
/// for them.
async fn assert_recovery_event_amount(restored: &Client, recovered_balance: u64) -> Result<()> {
    if FedimintCli::version_or_default().await < *VERSION_0_12_0_ALPHA {
        return Ok(());
    }

    // The event is ordered into the log asynchronously after recovery, so poll
    // for it rather than reading once.
    for attempt in 0..20 {
        let event_log = cmd!(restored, "dev", "show-event-log", "--limit", "1000")
            .out_json()
            .await?;

        if let Some(event) = mint_recovery_completed(&event_log) {
            let amount = event
                .amount
                .expect("recovery-completed event must carry the recovered amount");

            almost_equal(recovered_balance, amount.msats, 25_000)
                .map_err(|err| anyhow::anyhow!("recovery event amount mismatch: {err}"))?;

            return Ok(());
        }

        if attempt + 1 < 20 {
            fedimint_core::task::sleep_in_test(
                "waiting for the recovery-completed event to be ordered into the log",
                std::time::Duration::from_millis(250),
            )
            .await;
        }
    }

    anyhow::bail!("mint module did not emit a recovery-completed event");
}

async fn test_recovery_with_backup(fed: &Federation) -> Result<()> {
    info!(target: LOG_DEVIMINT, "### Test mint recovery with backup");
    let client = fed.new_joined_client("mint-recovery-backup").await?;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    let pre_balance = client.balance().await?;
    info!(target: LOG_DEVIMINT, pre_balance, "Balance before backup");
    assert!(pre_balance > 0);

    cmd!(client, "backup").run().await?;

    let restored = client
        .new_restored("mint-restored-with-backup", fed.invite_code()?)
        .await?;
    cmd!(restored, "dev", "wait-complete").out_json().await?;

    let post_balance = restored.balance().await?;
    info!(target: LOG_DEVIMINT, post_balance, "Balance after recovery with backup");
    almost_equal(pre_balance, post_balance, 25_000).unwrap();
    assert_recovery_event_amount(&restored, post_balance).await?;
    Ok(())
}

async fn test_recovery_without_backup(fed: &Federation) -> Result<()> {
    info!(target: LOG_DEVIMINT, "### Test mint recovery without backup");
    let client = fed.new_joined_client("mint-recovery-no-backup").await?;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    let pre_balance = client.balance().await?;
    assert!(pre_balance > 0);

    let restored = client
        .new_restored("mint-restored-no-backup", fed.invite_code()?)
        .await?;
    cmd!(restored, "dev", "wait-complete").out_json().await?;

    let post_balance = restored.balance().await?;
    info!(target: LOG_DEVIMINT, post_balance, "Balance after recovery without backup");
    almost_equal(pre_balance, post_balance, 25_000).unwrap();
    assert_recovery_event_amount(&restored, post_balance).await?;
    Ok(())
}

async fn test_recovery_after_activity(fed: &Federation) -> Result<()> {
    info!(target: LOG_DEVIMINT, "### Test mint recovery after spend+reissue activity");
    let client = fed
        .new_joined_client("mint-recovery-after-activity")
        .await?;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    for i in 0..3 {
        let balance = client.balance().await?;
        let spend_amount = balance / 3;

        let notes = cmd!(client, "spend", spend_amount)
            .out_json()
            .await?
            .get("notes")
            .expect("Output didn't contain e-cash notes")
            .as_str()
            .unwrap()
            .to_owned();

        cmd!(client, "reissue", notes).out_json().await?;
        info!(target: LOG_DEVIMINT, i, spend_amount, "Spent and reissued to self");
    }

    let pre_balance = client.balance().await?;
    info!(target: LOG_DEVIMINT, pre_balance, "Balance after activity");
    assert!(pre_balance > 0);

    cmd!(client, "backup").run().await?;

    let restored = client
        .new_restored("mint-restored-after-activity", fed.invite_code()?)
        .await?;
    cmd!(restored, "dev", "wait-complete").out_json().await?;

    let post_balance = restored.balance().await?;
    info!(target: LOG_DEVIMINT, post_balance, "Balance after recovery post-activity");
    almost_equal(pre_balance, post_balance, 25_000).unwrap();
    assert_recovery_event_amount(&restored, post_balance).await?;
    Ok(())
}

async fn test_recovery_with_post_backup_activity(fed: &Federation) -> Result<()> {
    info!(target: LOG_DEVIMINT, "### Test mint recovery with post-backup activity");
    let client = fed.new_joined_client("mint-recovery-post-backup").await?;
    fed.pegin_client(PEGIN_SATS, &client).await?;

    cmd!(client, "backup").run().await?;

    let balance = client.balance().await?;
    let spend_amount = balance / 2;
    let notes = cmd!(client, "spend", spend_amount)
        .out_json()
        .await?
        .get("notes")
        .expect("Output didn't contain e-cash notes")
        .as_str()
        .unwrap()
        .to_owned();
    cmd!(client, "reissue", notes).out_json().await?;

    let pre_balance = client.balance().await?;
    info!(target: LOG_DEVIMINT, pre_balance, "Balance after post-backup activity");

    let restored = client
        .new_restored("mint-restored-post-backup", fed.invite_code()?)
        .await?;
    cmd!(restored, "dev", "wait-complete").out_json().await?;

    let post_balance = restored.balance().await?;
    info!(target: LOG_DEVIMINT, post_balance, "Balance after recovery with post-backup activity");
    almost_equal(pre_balance, post_balance, 25_000).unwrap();
    assert_recovery_event_amount(&restored, post_balance).await?;
    Ok(())
}

async fn sanity() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|_fed, _process_mgr| async move { Ok(()) })
        .await
}
