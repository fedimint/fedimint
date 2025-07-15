use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_stream::try_stream;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::module::ClientModule;
use fedimint_client::secret::RootSecretStrategy;
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_core::config::FederationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{BoxFuture, BoxStream};
use fedimint_derive_secret::{ChildId, DerivableSecret};
use fedimint_ln_client::{LightningClientInit, LightningClientModule};
use fedimint_meta_client::MetaClientInit;
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use futures::StreamExt;
use futures::future::{AbortHandle, Abortable};
use lightning_invoice::Bolt11InvoiceDescriptionRef;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::info;

// Key prefixes for the unified database
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DbKeyPrefix {
    ClientDatabase = 0x00,
    Mnemonic = 0x01,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct MnemonicKey;

impl_db_record!(
    key = MnemonicKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::Mnemonic,
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RpcRequest {
    pub request_id: u64,
    #[serde(flatten)]
    pub kind: RpcRequestKind,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcRequestKind {
    SetMnemonic {
        words: Vec<String>,
    },
    GenerateMnemonic,
    GetMnemonic,
    /// Join federation (requires mnemonic to be set first)
    JoinFederation {
        invite_code: String,
        client_name: String,
    },
    OpenClient {
        client_name: String,
    },
    CloseClient {
        client_name: String,
    },
    ClientRpc {
        client_name: String,
        module: String,
        method: String,
        payload: serde_json::Value,
    },
    CancelRpc {
        cancel_request_id: u64,
    },
    ParseInviteCode {
        invite_code: String,
    },
    ParseBolt11Invoice {
        invoice: String,
    },
    PreviewFederation {
        invite_code: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RpcResponse {
    pub request_id: u64,
    #[serde(flatten)]
    pub kind: RpcResponseKind,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcResponseKind {
    Data { data: serde_json::Value },
    Error { error: String },
    Aborted {},
    End {},
}

pub trait RpcResponseHandler: MaybeSend + MaybeSync {
    fn handle_response(&self, response: RpcResponse);
}

pub struct RpcGlobalState {
    clients: Mutex<HashMap<String, ClientHandleArc>>,
    rpc_handles: std::sync::Mutex<HashMap<u64, AbortHandle>>,
    unified_database: Database,
}

pub struct HandledRpc<'a> {
    pub task: Option<BoxFuture<'a, ()>>,
}

impl RpcGlobalState {
    pub fn new(unified_database: Database) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            rpc_handles: std::sync::Mutex::new(HashMap::new()),
            unified_database,
        }
    }

    async fn add_client(&self, client_name: String, client: ClientHandleArc) {
        let mut clients = self.clients.lock().await;
        clients.insert(client_name, client);
    }

    async fn get_client(&self, client_name: &str) -> Option<ClientHandleArc> {
        let clients = self.clients.lock().await;
        clients.get(client_name).cloned()
    }

    fn add_rpc_handle(&self, request_id: u64, handle: AbortHandle) {
        let mut handles = self.rpc_handles.lock().unwrap();
        if handles.insert(request_id, handle).is_some() {
            tracing::error!("RPC CLIENT ERROR: request id reuse detected");
        }
    }

    fn remove_rpc_handle(&self, request_id: u64) -> Option<AbortHandle> {
        let mut handles = self.rpc_handles.lock().unwrap();
        handles.remove(&request_id)
    }

    async fn client_builder(db: Database) -> Result<fedimint_client::ClientBuilder, anyhow::Error> {
        let mut builder = fedimint_client::Client::builder(db).await?;
        builder.with_module(MintClientInit);
        builder.with_module(LightningClientInit::default());
        builder.with_module(WalletClientInit(None));
        builder.with_module(MetaClientInit);
        builder.with_primary_module_kind(fedimint_mint_client::KIND);
        Ok(builder)
    }

    /// Get client-specific database with proper prefix
    async fn client_db(&self, client_name: String) -> anyhow::Result<Database> {
        assert_eq!(client_name.len(), 36);

        let unified_db = &self.unified_database;
        let mut client_prefix = vec![DbKeyPrefix::ClientDatabase as u8];
        client_prefix.extend_from_slice(client_name.as_bytes());
        Ok(unified_db.with_prefix(client_prefix))
    }

    /// Handle joining federation using unified database
    async fn handle_join_federation(
        &self,
        invite_code: String,
        client_name: String,
    ) -> anyhow::Result<()> {
        // Check if wallet mnemonic is set
        let mnemonic = self
            .get_mnemonic_from_db()
            .await?
            .context("No wallet mnemonic set. Please set or generate a mnemonic first.")?;

        let client_db = self.client_db(client_name.clone()).await?;

        let invite_code = InviteCode::from_str(&invite_code)?;
        let federation_id = invite_code.federation_id();

        // Derive federation-specific secret from wallet mnemonic
        let federation_secret = self.derive_federation_secret(&mnemonic, &federation_id);

        let builder = Self::client_builder(client_db).await?;
        let client = Arc::new(
            builder
                .preview(&invite_code)
                .await?
                .join(RootSecret::StandardDoubleDerive(federation_secret))
                .await?,
        );

        self.add_client(client_name, client).await;
        Ok(())
    }

    async fn handle_open_client(&self, client_name: String) -> anyhow::Result<()> {
        // Check if wallet mnemonic is set
        let mnemonic = self
            .get_mnemonic_from_db()
            .await?
            .context("No wallet mnemonic set. Please set or generate a mnemonic first.")?;

        let client_db = self.client_db(client_name.clone()).await?;

        if !fedimint_client::Client::is_initialized(&client_db).await {
            anyhow::bail!("client is not initialized for this database");
        }

        // Get the client config to retrieve the federation ID
        let client_config = fedimint_client::Client::get_config_from_db(&client_db)
            .await
            .context("Client config not found in database")?;

        let federation_id = client_config.calculate_federation_id();

        // Derive federation-specific secret from wallet mnemonic
        let federation_secret = self.derive_federation_secret(&mnemonic, &federation_id);

        let builder = Self::client_builder(client_db).await?;
        let client = Arc::new(
            builder
                .open(RootSecret::StandardDoubleDerive(federation_secret))
                .await?,
        );

        self.add_client(client_name, client).await;
        Ok(())
    }

    async fn handle_close_client(&self, client_name: String) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().await;
        let mut client = clients.remove(&client_name).context("client not found")?;

        // RPC calls might have cloned the client Arc before we remove the client.
        for attempt in 0.. {
            info!(attempt, "waiting for RPCs to drop the federation object");
            match Arc::try_unwrap(client) {
                Ok(client) => {
                    client.shutdown().await;
                    break;
                }
                Err(client_val) => client = client_val,
            }
            fedimint_core::task::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    fn handle_client_rpc(
        self: Arc<Self>,
        client_name: String,
        module: String,
        method: String,
        payload: serde_json::Value,
    ) -> BoxStream<'static, anyhow::Result<serde_json::Value>> {
        Box::pin(try_stream! {
            let client = self
                .get_client(&client_name)
                .await
                .with_context(|| format!("Client not found: {}", client_name))?;
            match module.as_str() {
                "" => {
                    let mut stream = client.handle_global_rpc(method, payload);
                    while let Some(item) = stream.next().await {
                        yield item?;
                    }
                }
                "ln" => {
                    let ln = client.get_first_module::<LightningClientModule>()?.inner();
                    let mut stream = ln.handle_rpc(method, payload).await;
                    while let Some(item) = stream.next().await {
                        yield item?;
                    }
                }
                "mint" => {
                    let mint = client.get_first_module::<MintClientModule>()?.inner();
                    let mut stream = mint.handle_rpc(method, payload).await;
                    while let Some(item) = stream.next().await {
                        yield item?;
                    }
                }
                "wallet" => {
                    let wallet = client
                        .get_first_module::<WalletClientModule>()?
                        .inner();
                    let mut stream = wallet.handle_rpc(method, payload).await;
                    while let Some(item) = stream.next().await {
                        yield item?;
                    }
                }
                _ => {
                    Err(anyhow::format_err!("module not found: {module}"))?;
                },
            };
        })
    }

    fn parse_invite_code(&self, invite_code: String) -> anyhow::Result<serde_json::Value> {
        let invite_code = InviteCode::from_str(&invite_code)?;

        Ok(json!({
            "url": invite_code.url(),
            "federation_id": invite_code.federation_id(),
        }))
    }

    fn parse_bolt11_invoice(&self, invoice_str: String) -> anyhow::Result<serde_json::Value> {
        let invoice = lightning_invoice::Bolt11Invoice::from_str(&invoice_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse Lightning invoice: {}", e))?;

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);
        let amount_sat = amount_msat as f64 / 1000.0;

        let expiry_seconds = invoice.expiry_time().as_secs();

        // memo
        let description = match invoice.description() {
            Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
            Bolt11InvoiceDescriptionRef::Hash(_) => "Description hash only".to_string(),
        };

        Ok(json!({
            "amount": amount_sat,
            "expiry": expiry_seconds,
            "memo": description,
        }))
    }

    async fn preview_federation(&self, invite_code: String) -> anyhow::Result<serde_json::Value> {
        let invite = InviteCode::from_str(&invite_code)?;
        let client_config = fedimint_api_client::api::net::Connector::default()
            .download_from_invite_code(&invite)
            .await?;
        let json_config = client_config.to_json();
        let federation_id = client_config.calculate_federation_id();

        Ok(json!({
            "config": json_config,
            "federation_id": federation_id.to_string(),
        }))
    }

    fn handle_rpc_inner(
        self: Arc<Self>,
        request: RpcRequest,
    ) -> Option<BoxStream<'static, anyhow::Result<serde_json::Value>>> {
        match request.kind {
            RpcRequestKind::SetMnemonic { words } => Some(Box::pin(try_stream! {
                self.set_mnemonic(words).await?;
                yield serde_json::json!({ "success": true });
            })),
            RpcRequestKind::GenerateMnemonic => Some(Box::pin(try_stream! {
                let words = self.generate_mnemonic().await?;
                yield serde_json::json!({ "mnemonic": words });
            })),
            RpcRequestKind::GetMnemonic => Some(Box::pin(try_stream! {
                let words = self.get_mnemonic_words().await?;
                yield serde_json::json!({ "mnemonic": words });
            })),
            RpcRequestKind::JoinFederation {
                invite_code,
                client_name,
            } => Some(Box::pin(try_stream! {
                self.handle_join_federation(invite_code, client_name)
                    .await?;
                yield serde_json::json!(null);
            })),
            RpcRequestKind::OpenClient { client_name } => Some(Box::pin(try_stream! {
                self.handle_open_client(client_name).await?;
                yield serde_json::json!(null);
            })),
            RpcRequestKind::CloseClient { client_name } => Some(Box::pin(try_stream! {
                self.handle_close_client(client_name).await?;
                yield serde_json::json!(null);
            })),
            RpcRequestKind::ClientRpc {
                client_name,
                module,
                method,
                payload,
            } => Some(self.handle_client_rpc(client_name, module, method, payload)),
            RpcRequestKind::ParseInviteCode { invite_code } => Some(Box::pin(try_stream! {
                let result = self.parse_invite_code(invite_code)?;
                yield result;
            })),
            RpcRequestKind::ParseBolt11Invoice { invoice } => Some(Box::pin(try_stream! {
                let result = self.parse_bolt11_invoice(invoice)?;
                yield result;
            })),
            RpcRequestKind::PreviewFederation { invite_code } => Some(Box::pin(try_stream! {
                let result = self.preview_federation(invite_code).await?;
                yield result;
            })),
            RpcRequestKind::CancelRpc { cancel_request_id } => {
                if let Some(handle) = self.remove_rpc_handle(cancel_request_id) {
                    handle.abort();
                }
                None
            }
        }
    }

    pub fn handle_rpc(
        self: Arc<Self>,
        request: RpcRequest,
        handler: impl RpcResponseHandler + 'static,
    ) -> HandledRpc<'static> {
        let request_id = request.request_id;

        let Some(stream) = self.clone().handle_rpc_inner(request) else {
            return HandledRpc { task: None };
        };

        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        self.add_rpc_handle(request_id, abort_handle);

        let task = Box::pin(async move {
            let mut stream = Abortable::new(stream, abort_registration);

            while let Some(result) = stream.next().await {
                let response = match result {
                    Ok(value) => RpcResponse {
                        request_id,
                        kind: RpcResponseKind::Data { data: value },
                    },
                    Err(e) => RpcResponse {
                        request_id,
                        kind: RpcResponseKind::Error {
                            error: e.to_string(),
                        },
                    },
                };
                handler.handle_response(response);
            }

            // Clean up abort handle and send end message
            let _ = self.remove_rpc_handle(request_id);
            handler.handle_response(RpcResponse {
                request_id,
                kind: if stream.is_aborted() {
                    RpcResponseKind::Aborted {}
                } else {
                    RpcResponseKind::End {}
                },
            });
        });

        HandledRpc { task: Some(task) }
    }

    /// Retrieve the wallet-level mnemonic words.
    /// Returns the mnemonic as a vector of words, or None if no mnemonic is
    /// set.
    async fn get_mnemonic_words(&self) -> anyhow::Result<Option<Vec<String>>> {
        let mnemonic = self.get_mnemonic_from_db().await?;

        if let Some(mnemonic) = mnemonic {
            let words = mnemonic.words().map(|w| w.to_string()).collect();
            Ok(Some(words))
        } else {
            Ok(None)
        }
    }
    /// Set a mnemonic from user-provided words
    /// Returns an error if a mnemonic is already set
    async fn set_mnemonic(&self, words: Vec<String>) -> anyhow::Result<()> {
        let all_words = words.join(" ");
        let mnemonic =
            Mnemonic::parse_in_normalized(fedimint_bip39::Language::English, &all_words)?;

        let mut dbtx = self.unified_database.begin_transaction().await;

        if dbtx.get_value(&MnemonicKey).await.is_some() {
            anyhow::bail!(
                "Wallet mnemonic already exists. Please clear existing data before setting a new mnemonic."
            );
        }

        dbtx.insert_new_entry(&MnemonicKey, &mnemonic.to_entropy())
            .await;

        dbtx.commit_tx().await;

        Ok(())
    }

    /// Generate a new random mnemonic and set it
    /// Returns an error if a mnemonic is already set
    async fn generate_mnemonic(&self) -> anyhow::Result<Vec<String>> {
        let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut thread_rng());
        let words: Vec<String> = mnemonic.words().map(|w| w.to_string()).collect();

        let mut dbtx = self.unified_database.begin_transaction().await;

        if dbtx.get_value(&MnemonicKey).await.is_some() {
            anyhow::bail!(
                "Wallet mnemonic already exists. Please clear existing data before generating a new mnemonic."
            );
        }

        dbtx.insert_new_entry(&MnemonicKey, &mnemonic.to_entropy())
            .await;

        dbtx.commit_tx().await;

        Ok(words)
    }

    /// Derive federation-specific secret from wallet mnemonic
    fn derive_federation_secret(
        &self,
        mnemonic: &Mnemonic,
        federation_id: &FederationId,
    ) -> DerivableSecret {
        let global_root_secret = Bip39RootSecretStrategy::<12>::to_root_secret(mnemonic);
        let multi_federation_root_secret = global_root_secret.child_key(ChildId(0));
        let federation_root_secret = multi_federation_root_secret.federation_key(federation_id);
        let federation_wallet_root_secret = federation_root_secret.child_key(ChildId(0));
        federation_wallet_root_secret.child_key(ChildId(0))
    }

    /// Fetch mnemonic from database
    async fn get_mnemonic_from_db(&self) -> anyhow::Result<Option<Mnemonic>> {
        let mut dbtx = self.unified_database.begin_transaction_nc().await;

        if let Some(mnemonic_entropy) = dbtx.get_value(&MnemonicKey).await {
            let mnemonic = Mnemonic::from_entropy(&mnemonic_entropy)?;
            Ok(Some(mnemonic))
        } else {
            Ok(None)
        }
    }
}
