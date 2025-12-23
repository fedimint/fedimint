use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use devimint::cmd;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::Amount;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_mint_client::{MintClientInit, MintClientModule, OOBNotes, ReissueExternalNotesState};
use fedimint_wallet_client::WalletClientInit;
use futures::StreamExt;
use futures::future::try_join_all;
use tracing::info;

const PEGIN_SATS: u64 = 1_000 * 100_000_000; // 1k BTC
const CLIENT_SATS: u64 = 100_000_000; // 1 BTC per client
const REISSUE_AMOUNT: Amount = Amount::from_sats(10_000);

#[derive(Parser)]
struct Args {
    #[arg(default_value = "10")]
    num_clients: usize,

    #[arg(default_value = "10")]
    reissues_per_client: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        num_clients,
        reissues_per_client,
    } = Args::parse();

    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            let federation = dev_fed.fed().await?;

            let invite_code: InviteCode = federation.invite_code()?.parse()?;
            info!("Invite code: {invite_code}");
            info!(
                "Starting reissue load test: {num_clients} clients x {reissues_per_client} reissues"
            );

            // Fund the internal client first using pegin (100 BTC)
            let internal_client = federation.internal_client().await?;
            federation.pegin_client(PEGIN_SATS, internal_client).await?;
            info!("Internal client funded with {} sats", PEGIN_SATS);

            // Create native rust clients in parallel
            let client_futures: Vec<_> = (0..num_clients)
                .map(|i| build_native_client(&invite_code, i))
                .collect();
            let clients = try_join_all(client_futures).await?;
            info!("All {} native clients created", clients.len());

            // Transfer initial funds from internal client to each native client
            // by spending notes and reissuing them
            for (i, client) in clients.iter().enumerate() {
                // Use CLI to spend notes from internal client (10M sats = 10B msats per client)
                let notes_json = cmd!(
                    internal_client,
                    "spend",
                    "--allow-overpay",
                    (CLIENT_SATS * 1000).to_string()
                )
                .out_json()
                .await?;
                let notes_str = notes_json["notes"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing notes field"))?;
                let oob_notes = OOBNotes::from_str(notes_str)?;

                // Reissue to native client
                let mint = client.get_first_module::<MintClientModule>()?;
                let op = mint.reissue_external_notes(oob_notes, ()).await?;
                let mut updates = mint
                    .subscribe_reissue_external_notes(op)
                    .await?
                    .into_stream();
                while let Some(update) = updates.next().await {
                    match update {
                        ReissueExternalNotesState::Done => break,
                        ReissueExternalNotesState::Failed(e) => {
                            anyhow::bail!("Initial reissue failed: {e}");
                        }
                        _ => {}
                    }
                }
                info!("Client {i}: funded with initial balance");
            }

            info!("All clients funded, starting reissues...");

            // Run reissue tests in parallel using native Rust API
            let tasks: Vec<_> = clients
                .into_iter()
                .enumerate()
                .map(|(i, client)| run_client_test(client, i, reissues_per_client))
                .collect();

            try_join_all(tasks).await?;

            info!("Reissue load test complete!");

            fedimint_core::runtime::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;

            Ok(())
        })
        .await
}

async fn build_native_client(
    invite_code: &InviteCode,
    client_id: usize,
) -> Result<ClientHandleArc> {
    // Create in-memory database for speed
    let db = Database::new(
        fedimint_core::db::mem_impl::MemDatabase::new(),
        ModuleRegistry::default(),
    );

    let mut client_builder = Client::builder().await?;
    client_builder.with_module(MintClientInit);
    client_builder.with_module(WalletClientInit::default());

    let client_secret = Client::load_or_generate_client_secret(&db).await?;
    let root_secret =
        RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&client_secret));

    let connectors = ConnectorRegistry::build_from_client_env()?.bind().await?;

    // Join the federation
    let client = client_builder
        .preview(connectors, invite_code)
        .await?
        .join(db, root_secret)
        .await?;

    info!("Native client {client_id}: created and joined");

    Ok(Arc::new(client))
}

async fn run_client_test(
    client: ClientHandleArc,
    client_id: usize,
    reissues_per_client: usize,
) -> Result<()> {
    let mint = client.get_first_module::<MintClientModule>()?;

    for i in 0..reissues_per_client {
        // Send OOB notes (spend from our balance)
        let notes = mint.send_oob_notes(REISSUE_AMOUNT, ()).await?;

        // Reissue notes back to ourselves
        let reissue_op = mint.reissue_external_notes(notes, ()).await?;

        // Wait for reissue to complete
        let mut updates = mint
            .subscribe_reissue_external_notes(reissue_op)
            .await?
            .into_stream();
        while let Some(update) = updates.next().await {
            match update {
                ReissueExternalNotesState::Done => break,
                ReissueExternalNotesState::Failed(e) => {
                    anyhow::bail!("Reissue failed: {e}");
                }
                _ => {}
            }
        }

        if (i + 1) % 25 == 0 {
            info!(
                "Client {client_id}: {}/{reissues_per_client} reissues",
                i + 1
            );
        }
    }

    info!("Client {client_id}: completed all reissues");

    Ok(())
}
