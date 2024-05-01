use anyhow::Context;
use devimint::cmd;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|fed| async move {
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
