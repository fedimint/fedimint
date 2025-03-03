use anyhow::{Context as _, Result};
use clap::Parser;
use devimint::cmd;
use devimint::federation::Federation;
use devimint::util::FedimintCli;
use devimint::version_constants::VERSION_0_5_0_ALPHA;
use fedimint_logging::LOG_DEVIMINT;
use rand::Rng;
use tracing::info;

#[derive(Debug, Parser)]
enum Cmd {
    Restore,
    Sanity,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cmd::parse() {
        Cmd::Restore => restore().await,
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
    let fedimint_cli_version = FedimintCli::version_or_default().await;

    if fedimint_cli_version < *VERSION_0_5_0_ALPHA {
        return Ok(());
    }

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
            // we are not guarantted to use a 1024 note on every payment,
            // so create some random small gaps, so it's very unlikely we
            // would cross the default gap limit accidentally
            &gap.to_string()
        )
        .run()
        .await?;

        let reissure_amount_sats = if i % 2 == 0 {
            // half of the time, reissue everything
            PEGIN_SATS
        } else {
            // other half, random amount
            rand::thread_rng().gen_range(10..PEGIN_SATS)
        };
        info!(target: LOG_DEVIMINT, i, reissure_amount_sats, "Reissue");

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

async fn sanity() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|fed, _process_mgr| async move {
            let fed = fed.fed().await?;

            test_note_consoliation(fed).await?;
            Ok(())
        })
        .await
}

/// Test note consolidation, which at the time of writing basically means that
/// once client accumulates too many notes of certain denomination, any
/// transaction building will include excessive notes as extra inputs, to
/// consolidate them into higher denominations.
///
/// In the future we will probably change the whole thing and delete this thing.
async fn test_note_consoliation(fed: &devimint::federation::Federation) -> anyhow::Result<()> {
    let sender = fed.new_joined_client("sender").await?;
    let receiver = fed.new_joined_client("receiver").await?;

    let can_no_wait = cmd!(sender, "reissue", "--help")
        .out_string()
        .await?
        .contains("no-wait");

    if !can_no_wait {
        info!("Version before `--no-wait` didn't have consolidation implemented");
        return Ok(());
    }
    fed.pegin_client(10_000, &sender).await?;

    let mut all_notes = vec![];
    for i in 0..20 {
        let info = cmd!(sender, "info").out_json().await?;
        info!(%info, "sender info");
        // remint sender notes from time to time to make sure it have 1msat notes
        if i % 2 == 1 {
            let notes = cmd!(sender, "spend", "1sat",).out_json().await?["notes"]
                .as_str()
                .context("invoice must be string")?
                .to_owned();

            cmd!(sender, "reissue", notes).run().await?;
        }

        let notes = cmd!(sender, "spend", "1msat",).out_json().await?["notes"]
            .as_str()
            .context("invoice must be string")?
            .to_owned();

        all_notes.push(notes);
    }

    for notes in &all_notes[..all_notes.len() - 1] {
        cmd!(receiver, "reissue", "--no-wait", notes).run().await?;
    }

    // wait for all at the same time to make things go faster
    cmd!(receiver, "dev", "wait-complete").run().await?;

    // reissuance of last note will trigger consolidation
    cmd!(receiver, "reissue")
        .args(&all_notes[all_notes.len() - 1..])
        .run()
        .await?;

    let info = cmd!(receiver, "info").out_json().await?;
    info!(%info, "receiver info");
    // receiver has the balance
    assert_eq!(info["total_amount_msat"].as_i64().unwrap(), 20);
    // without the consolidation, this would be 20 1msat notes
    assert!(info["denominations_msat"]["1"].as_i64().unwrap() < 20);

    Ok(())
}
