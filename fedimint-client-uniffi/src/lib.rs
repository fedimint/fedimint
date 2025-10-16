use std::sync::Arc;

use fedimint_client_rpc::{RpcGlobalState, RpcRequest, RpcResponse, RpcResponseHandler};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::Database;

uniffi::setup_scaffolding!();

const DB_FILE_NAME: &str = "fedimint.redb";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FedimintError {
    #[error("Database initialization failed: {msg}")]
    DatabaseError { msg: String },

    #[error("Failed to initialize networking: {msg}")]
    NetworkingError { msg: String },

    #[error("Failed to create async runtime: {msg}")]
    RuntimeError { msg: String },

    #[error("Invalid request JSON: {msg}")]
    InvalidRequest { msg: String },

    #[error("General error: {msg}")]
    General { msg: String },
}

#[derive(uniffi::Object)]
pub struct RpcHandler {
    state: Arc<RpcGlobalState>,
    runtime: tokio::runtime::Runtime,
}

#[uniffi::export]
impl RpcHandler {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> Result<Arc<Self>, FedimintError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| FedimintError::RuntimeError { msg: e.to_string() })?;

        let state = runtime.block_on(async {
            let connectors = ConnectorRegistry::build_from_client_env()
                .map_err(|e| FedimintError::General { msg: e.to_string() })?
                .bind()
                .await
                .map_err(|e| FedimintError::NetworkingError { msg: e.to_string() })?;
            let db = create_database(&db_path)
                .await
                .map_err(|e| FedimintError::DatabaseError { msg: e.to_string() })?;

            Ok(Arc::new(RpcGlobalState::new(connectors, db)))
        })?;

        Ok(Arc::new(Self { state, runtime }))
    }

    pub async fn rpc(&self, request_json: String) -> Result<String, FedimintError> {
        let request: RpcRequest = serde_json::from_str(&request_json)
            .map_err(|e| FedimintError::InvalidRequest { msg: e.to_string() })?;

        let (tx, rx) = tokio::sync::oneshot::channel();

        let handled = self
            .state
            .clone()
            .handle_rpc(request, PromiseWrapper(std::sync::Mutex::new(Some(tx))));

        if let Some(task) = handled.task {
            self.runtime.spawn(task);
        }

        rx.await.map_err(|_| FedimintError::General {
            msg: "Request cancelled or handler dropped".to_string(),
        })
    }
}

struct PromiseWrapper(std::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>);

impl RpcResponseHandler for PromiseWrapper {
    fn handle_response(&self, response: RpcResponse) {
        let json = serde_json::to_string(&response).expect("Failed to serialize RPC response");
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(json);
        }
    }
}

async fn create_database(path: &str) -> anyhow::Result<Database> {
    tokio::fs::create_dir_all(path).await?;

    let db_path = std::path::Path::new(path).join(DB_FILE_NAME);
    let db = fedimint_rocksdb::RocksDb::open(db_path).await?;

    Ok(Database::new(db, Default::default()))
}
