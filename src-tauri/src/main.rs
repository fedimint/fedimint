#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod db;

use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use db::create_database;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{Client, ClientHandle};
use fedimint_core::Amount;
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_derive_secret::DerivableSecret;
use fedimint_ln_client::LightningClientInit;
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;
use serde::{Deserialize, Serialize};
use tauri::async_runtime::Mutex;
use tauri::{Manager, State};

#[derive(Serialize, Deserialize)]
struct InviteCodeInfo {
    federation_name: Option<String>,
    federation_id: String,
}

#[derive(Serialize, Deserialize)]
struct WalletInfo {
    total_balance_msat: Amount,
    client_name: String,
    // federation_name: Option<String>,
    federation_id: String,
    // mnemonic: String,
}

#[derive(Default)]
struct ClientState {
    active_client: Mutex<Option<Arc<ClientHandle>>>,
}

#[tauri::command]
async fn parse_invite_code(invite_code: String) -> Result<InviteCodeInfo, String> {
    let invite =
        InviteCode::from_str(&invite_code).map_err(|e| format!("Invalid invite code: {}", e))?;

    Ok(InviteCodeInfo {
        federation_name: None,
        federation_id: invite.federation_id().to_string(),
    })
}

// Create a new client and join a federation
#[tauri::command]
async fn join_federation(
    app_handle: tauri::AppHandle,
    invite_code: String,
    client_name: String,
    client_state: State<'_, ClientState>,
) -> Result<WalletInfo, String> {
    let (client_handle, config) =
        join_federation_inner(app_handle, invite_code, client_name.clone())
            .await
            .map_err(|e| format!("Failed to join federation: {}", e))?;
    let balance = client_handle.get_balance().await;
    println!("Successfully joined federation, balance: {} msat", balance);
    *client_state.active_client.lock().await = Some(Arc::new(client_handle));
    Ok(WalletInfo {
        total_balance_msat: balance,
        client_name,
        federation_id: config.calculate_federation_id().to_string(),
    })
}

async fn client_builder(db: Database) -> Result<fedimint_client::ClientBuilder, anyhow::Error> {
    let mut builder = fedimint_client::Client::builder(db).await?;
    builder.with_module(MintClientInit);
    builder.with_module(LightningClientInit::default());
    builder.with_primary_module(1);
    Ok(builder)
}

// Open an existing client
#[tauri::command]
async fn open_client(
    app_handle: tauri::AppHandle,
    client_name: String,
    client_state: State<'_, ClientState>,
) -> Result<WalletInfo, String> {
    println!("Opening client with name: {}", client_name);
    let client_handle = open_client_inner(app_handle, client_name.clone())
        .await
        .map_err(|e| format!("Failed to open client: {}", e))?;
    let balance = client_handle.get_balance().await;
    let config = client_handle.config().await;
    let federation_id = config.calculate_federation_id().to_string();
    println!("Successfully opened client, balance: {} msat", balance);
    *client_state.active_client.lock().await = Some(Arc::new(client_handle));

    Ok(WalletInfo {
        total_balance_msat: balance,
        client_name,
        federation_id,
    })
}

// Generate a deposit address
// #[tauri::command]
// async fn generate_deposit_address(
//     client_state: State<'_, ClientState>
// ) -> Result<String, String> {
//     let client_guard = client_state.active_client.lock().await;
//     let client = client_guard
//         .as_ref()
//         .ok_or("No active client")?;

//     let wallet_module = client
//         .get_first_module_by_kind(&ModuleKind::from_static_str("wallet"))
//         .map_err(|e| format!("Failed to get wallet module: {}", e))?;

//     let (address, _) = wallet_module.get_deposit_address()
//         .await
//         .map_err(|e| format!("Failed to generate deposit address: {}", e))?;

//     Ok(address)
// }

#[tauri::command]
async fn check_active_client(client_state: State<'_, ClientState>) -> Result<bool, String> {
    let client_guard = client_state.active_client.lock().await;
    Ok(client_guard.is_some())
}

// Add this function to get client/wallet info if it exists
#[tauri::command]
async fn get_wallet_info(client_state: State<'_, ClientState>) -> Result<WalletInfo, String> {
    let client_guard = client_state.active_client.lock().await;
    let client = client_guard.as_ref().ok_or("No active client")?;

    get_wallet_info_inner(client)
        .await
        .map_err(|e| format!("Failed to get wallet info: {}", e))
}

// Helper function to join federation with all needed modules
async fn join_with_modules(
    db: Database,
    root_secret: DerivableSecret,
    config: fedimint_core::config::ClientConfig,
) -> Result<ClientHandle> {
    let mut builder = Client::builder(db).await?;
    builder.with_module(MintClientInit);
    builder.with_module(LightningClientInit::default());
    builder.with_module(WalletClientInit::default());
    builder.with_primary_module_kind(ModuleKind::from_static_str("mint"));
    let client_handle = builder.join(root_secret, config, None).await?;

    Ok(client_handle)
}

// Helper function to open existing client
async fn open_with_modules(db: Database, root_secret: DerivableSecret) -> Result<ClientHandle> {
    let mut builder = Client::builder(db).await?;
    builder.with_module(MintClientInit);
    builder.with_module(LightningClientInit::default());
    builder.with_module(WalletClientInit::default());
    builder.with_primary_module_kind(ModuleKind::from_static_str("mint"));
    let client_handle = builder.open(root_secret).await?;

    Ok(client_handle)
}

/// Inner implementation for joining a federation
async fn join_federation_inner(
    app_handle: tauri::AppHandle,
    invite_code: String,
    client_name: String,
) -> anyhow::Result<(ClientHandle, fedimint_core::config::ClientConfig)> {
    let invite = InviteCode::from_str(&invite_code).context("Invalid invite code")?;
    let db = create_database(app_handle, &client_name).await?;
    println!("Database created at:");
    let config = fedimint_api_client::api::net::Connector::default()
        .download_from_invite_code(&invite)
        .await
        .context("Failed to download config")?;
    println!("Config downloaded from invite code");
    let client_secret = Client::load_or_generate_client_secret(&db)
        .await
        .context("Failed to generate client secret")?;
    println!("Client secret generated {:?}", client_secret);
    let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
    let client_handle = join_with_modules(db, root_secret, config.clone())
        .await
        .context("Failed to join federation")?;
    println!("Client handle created");

    Ok((client_handle, config))
}

/// Inner implementation for opening an existing client
async fn open_client_inner(
    app_handle: tauri::AppHandle,
    client_name: String,
) -> anyhow::Result<ClientHandle> {
    // Create database
    let db = create_database(app_handle, &client_name).await?;
    if !Client::is_initialized(&db).await {
        return Err(anyhow!("Client not initialized"));
    }
    let client_secret = Client::load_or_generate_client_secret(&db)
        .await
        .context("Failed to load client secret")?;
    let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
    let client_handle = open_with_modules(db, root_secret)
        .await
        .context("Failed to open client")?;

    Ok(client_handle)
}

/// Inner implementation for getting wallet info
async fn get_wallet_info_inner(client: &ClientHandle) -> anyhow::Result<WalletInfo> {
    let balance = client.get_balance().await;
    let config = client.config().await;
    let federation_id = config.calculate_federation_id().to_string();
    let client_name = "active_client".to_string();

    Ok(WalletInfo {
        total_balance_msat: balance,
        client_name,
        federation_id,
    })
}

fn main() {
    tauri::Builder::default()
        .manage(ClientState::default())
        .invoke_handler(tauri::generate_handler![
            parse_invite_code,
            join_federation,
            open_client,
            check_active_client,
            get_wallet_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
