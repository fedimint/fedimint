use bitcoin_hashes::Hash;
use clap::Subcommand;
use fedimint_client::transaction::TransactionBuilder;
use fedimint_client::ClientBuilder;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{IntoDynInstance, LEGACY_HARDCODED_INSTANCE_ID_MINT};
use fedimint_core::db::IDatabase;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::{OutPoint, TieredMulti};
use fedimint_ln_client::LightningClientGen;
use fedimint_mint_client::{MintClientGen, MintClientModule, SpendableNote};
use fedimint_wallet_client::WalletClientGen;
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
            let info = mint_client
                .get_wallet_summary(
                    &mut client.db().begin_transaction().await.with_module_prefix(1),
                )
                .await;
            Ok(serde_json::to_value(info).unwrap())
        }
        ClientNg::Reissue { notes } => {
            let amt = notes.total_amount();

            let mint_client = client
                .get_module_client::<MintClientModule>(LEGACY_HARDCODED_INSTANCE_ID_MINT)
                .unwrap();

            let notes_hash = notes.consensus_hash().unwrap().into_inner();
            let mint_input = mint_client
                .create_input_from_notes(notes_hash, notes)
                .await
                .unwrap();

            let tx = TransactionBuilder::new()
                .with_input(mint_input.into_dyn(LEGACY_HARDCODED_INSTANCE_ID_MINT));

            let txid = client
                .finalize_and_submit_transaction(notes_hash, tx)
                .await
                .unwrap();

            info!("Transaction submitted: {}", txid);
            client.context().await_tx_accepted(notes_hash, txid).await;
            info!("Transaction accepted");
            mint_client
                .await_output_finalized(notes_hash, OutPoint { txid, out_idx: 0 })
                .await
                .unwrap();
            info!("Output finalized");

            Ok(serde_json::to_value(amt).unwrap())
        }
    }
}

pub fn parse_ecash(s: &str) -> anyhow::Result<TieredMulti<SpendableNote>> {
    let bytes = base64::decode(s)?;
    Ok(Decodable::consensus_decode(
        &mut std::io::Cursor::new(bytes),
        &ModuleDecoderRegistry::default(),
    )?)
}
