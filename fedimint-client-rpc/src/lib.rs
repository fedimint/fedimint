use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_stream::try_stream;
use fedimint_client::module::ClientModule;
use fedimint_client::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::{BoxFuture, BoxStream};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_ln_client::{LightningClientInit, LightningClientModule};
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_wallet_client::{WalletClientInit, WalletClientModule};
use futures::StreamExt;
use futures::future::{AbortHandle, Abortable};
use lightning_invoice::Bolt11InvoiceDescriptionRef;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RpcRequest {
    pub request_id: u64, // Unique identifier for each request
    #[serde(flatten)]
    pub kind: RpcRequestKind,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcRequestKind {
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

#[derive(Serialize, Deserialize)]
pub struct RpcResponse {
    pub request_id: u64,
    #[serde(flatten)]
    pub kind: RpcResponseKind,
}

#[derive(Serialize, Deserialize)]
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
// A trait for database creation (handles both new and existing databases).
#[apply(async_trait_maybe_send!)]
pub trait DatabaseFactory: MaybeSend + MaybeSync + 'static {
    async fn create_database(&self, name: &str) -> anyhow::Result<Database>;
}

pub struct RpcGlobalState<D> {
    clients: Mutex<HashMap<String, ClientHandleArc>>,
    rpc_handles: std::sync::Mutex<HashMap<u64, AbortHandle>>,
    db_factory: D,
}

pub struct HandledRpc<'a> {
    pub task: Option<BoxFuture<'a, ()>>,
}

impl<D: DatabaseFactory> RpcGlobalState<D> {
    pub fn new(db_factory: D) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            rpc_handles: std::sync::Mutex::new(HashMap::new()),
            db_factory,
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
        builder.with_primary_module_kind(fedimint_mint_client::KIND);
        Ok(builder)
    }

    async fn handle_join_federation(
        &self,
        invite_code: String,
        client_name: String,
    ) -> anyhow::Result<()> {
        let db = self.db_factory.create_database(&client_name).await?;
        let client_secret = fedimint_client::Client::load_or_generate_client_secret(&db).await?;
        let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
        let builder = Self::client_builder(db).await?;
        let invite_code = InviteCode::from_str(&invite_code)?;
        let client = Arc::new(
            builder
                .preview(&invite_code)
                .await?
                .join(RootSecret::StandardDoubleDerive(root_secret))
                .await?,
        );

        self.add_client(client_name, client).await;
        Ok(())
    }

    async fn handle_open_client(&self, client_name: String) -> anyhow::Result<()> {
        let db = self.db_factory.create_database(&client_name).await?;
        if !fedimint_client::Client::is_initialized(&db).await {
            anyhow::bail!("client is not initialized for this database");
        }

        let client_secret = fedimint_client::Client::load_or_generate_client_secret(&db).await?;
        let root_secret = PlainRootSecretStrategy::to_root_secret(&client_secret);
        let builder = Self::client_builder(db).await?;
        let client = Arc::new(
            builder
                .open(RootSecret::StandardDoubleDerive(root_secret))
                .await?,
        );

        self.add_client(client_name, client).await;
        Ok(())
    }

    async fn handle_close_client(&self, client_name: String) -> anyhow::Result<()> {
        let mut clients = self.clients.lock().await;
        let mut client = clients
            .remove(&client_name)
            .ok_or_else(|| anyhow::format_err!("client not found"))?;

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
                .ok_or_else(|| anyhow::format_err!("Client not found: {}", client_name))?;
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
                    unreachable!()
                },
            };
        })
    }

    fn parse_invite_code(&self, invite_code: String) -> anyhow::Result<serde_json::Value> {
        let invite_code = InviteCode::from_str(&invite_code)?;
        let federation_id = invite_code.federation_id().to_string();
        let url = invite_code.url().to_string();

        Ok(json!({
            "url": url,
            "federation_id": federation_id,
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
}
