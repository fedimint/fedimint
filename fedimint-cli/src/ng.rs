use clap::Subcommand;
use fedimint_client::ClientBuilder;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
use fedimint_core::db::IDatabase;
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::{Amount, TieredMulti, TieredSummary};
use fedimint_ln_client::LightningClientGen;
use fedimint_mint_client::{MintClientExt, MintClientGen, MintClientModule, SpendableNote};
use fedimint_wallet_client::WalletClientGen;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Subcommand)]
pub enum ClientNg {
    Info,
    Reissue {
        #[clap(value_parser = parse_ecash)]
        notes: TieredMulti<SpendableNote>,
    },
}

pub async fn handle_ng_command<D: IDatabase>(
    command: ClientNg,
    cfg: ClientConfig,
    db: D,
) -> anyhow::Result<serde_json::Value> {
    let mut tg = TaskGroup::new();

    let mut client_builder = ClientBuilder::default();
    client_builder.with_module(MintClientGen);
    client_builder.with_module(LightningClientGen);
    client_builder.with_module(WalletClientGen);
    client_builder.with_primary_module(1);
    client_builder.with_config(cfg);
    let client = client_builder.build(db, &mut tg).await?;

    match command {
        ClientNg::Info => {
            let mint_client = client
                .get_module_client::<MintClientModule>(LEGACY_HARDCODED_INSTANCE_ID_MINT)
                .unwrap();
            let summary = mint_client
                .get_wallet_summary(
                    &mut client.db().begin_transaction().await.with_module_prefix(1),
                )
                .await;
            Ok(serde_json::to_value(InfoResponse {
                total_msat: summary.total_amount(),
                denominations_msat: summary,
            })
            .unwrap())
        }
        ClientNg::Reissue { notes } => {
            let amount = notes.total_amount();

            let operation_id = client.reissue_external_notes(notes).await?;
            let mut updates = client
                .subscribe_reissue_external_notes_updates(operation_id)
                .await
                .unwrap();

            while let Some(update) = updates.next().await {
                if let fedimint_mint_client::ReissueExternalNotesState::Failed(e) = update {
                    return Err(anyhow::Error::msg(format!("Reissue failed: {e}")));
                }

                info!("Update: {:?}", update);
            }

            Ok(serde_json::to_value(amount).unwrap())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InfoResponse {
    total_msat: Amount,
    denominations_msat: TieredSummary,
}

pub fn parse_ecash(s: &str) -> anyhow::Result<TieredMulti<SpendableNote>> {
    let bytes = base64::decode(s)?;
    Ok(Decodable::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}
