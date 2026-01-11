use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{Client, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_mint_client::MintClientInit;
use futures::StreamExt;
use rand::thread_rng;
use tracing::info;

#[derive(Parser)]
struct Args {
    invite_code: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;

    let args = Args::parse();
    let invite_code = InviteCode::from_str(&args.invite_code)?;

    // Generate a random mnemonic for testing
    let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut thread_rng());
    info!("Generated mnemonic: {}", mnemonic);

    let root_secret =
        RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic));

    // Create in-memory database
    let db = Database::new(
        fedimint_core::db::mem_impl::MemDatabase::new(),
        Default::default(),
    );

    // Build client with only mint module
    let mut client_builder = Client::builder().await?;
    client_builder.with_module(MintClientInit);

    let connectors = ConnectorRegistry::build_from_client_defaults()
        .iroh_next(false)
        .bind()
        .await?;

    info!("Connecting to federation...");
    let preview = client_builder.preview(connectors, &invite_code).await?;

    info!("Starting recovery...");
    let client = preview.recover(db, root_secret, None).await?;

    // Wait for recovery to complete
    let mut progress_stream = client.subscribe_to_recovery_progress();
    let mut total_items = 0u32;

    // Wait for initial 0/0 progress update
    let _ = progress_stream.next().await;
    let start = fedimint_core::time::now();

    while let Some((_module_id, progress)) = progress_stream.next().await {
        if progress.is_done() {
            break;
        }
        total_items = total_items.max(progress.total);
    }

    let elapsed = fedimint_core::time::now()
        .duration_since(start)
        .unwrap_or(Duration::ZERO);
    let items_per_sec = total_items as f64 / elapsed.as_secs_f64();
    info!(
        "Recovery complete! {} items in {:.2}s = {:.0} items/sec",
        total_items,
        elapsed.as_secs_f64(),
        items_per_sec
    );

    Ok(())
}
