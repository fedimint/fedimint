#![deny(clippy::pedantic)]
#![allow(clippy::large_futures)]
#![allow(dead_code)]
#![allow(clippy::literal_string_with_formatting_args)]

use std::sync::Arc;

use anyhow::Result;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::invite_code::InviteCode;
use fedimint_ln_client::{LightningClientInit, LightningClientModule};
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use rand::thread_rng;

async fn load_or_generate_mnemonic(db: &Database) -> anyhow::Result<[u8; 64]> {
    Ok(
        if let Ok(s) = Client::load_decodable_client_secret(db).await {
            s
        } else {
            let secret = PlainRootSecretStrategy::random(&mut thread_rng());
            Client::store_encodable_client_secret(db, secret).await?;
            secret
        },
    )
}

async fn make_client_builder() -> Result<(fedimint_client::ClientBuilder, Database)> {
    let mem_database = MemDatabase::default();
    let mut builder = fedimint_client::Client::builder().await;
    builder.with_module(LightningClientInit::default());
    builder.with_module(MintClientInit);
    builder.with_module(WalletClientInit::default());

    Ok((builder, mem_database.into()))
}

async fn client(invite_code: &InviteCode) -> Result<fedimint_client::ClientHandleArc> {
    let (mut builder, db) = make_client_builder().await?;
    let client_secret = load_or_generate_mnemonic(&db).await?;
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await;
    builder.stopped();
    let client = builder
        .preview(connectors, invite_code)
        .await?
        .join(
            db,
            RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(
                &client_secret,
            )),
        )
        .await
        .map(Arc::new)?;
    if let Ok(ln_client) = client.get_first_module::<LightningClientModule>() {
        let _ = ln_client.update_gateway_cache().await;
    }
    Ok(client)
}

mod faucet;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
mod tests;
