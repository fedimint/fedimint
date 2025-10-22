use std::sync::Arc;

use fedimint_client_rpc::{RpcGlobalState, RpcRequest, RpcResponse, RpcResponseHandler};
use fedimint_core::db::Database;

uniffi::setup_scaffolding!();

const DB_FILE_NAME: &str = "fedimint.redb";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FedimintError {
    #[error("Database initialization failed: {msg}")]
    DatabaseError { msg: String },
    
    #[error("Failed to create async runtime: {msg}")]
    RuntimeError { msg: String },
    
    #[error("Invalid request JSON: {msg}")]
    InvalidRequest { msg: String },
    
    #[error("General error: {msg}")]
    General { msg: String },
}

#[uniffi::export(callback_interface)]
pub trait RpcCallback: Send + Sync {
    fn on_response(&self, response_json: String);
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
        
        let db = create_database(&db_path, &runtime)
            .map_err(|e| FedimintError::DatabaseError { msg: e.to_string() })?;
        let state = Arc::new(RpcGlobalState::new(db));
        
        Ok(Arc::new(Self { state, runtime }))
    }

    pub fn rpc(&self, request_json: String, callback: Box<dyn RpcCallback>) -> Result<(), FedimintError> {
        let request: RpcRequest = serde_json::from_str(&request_json)
            .map_err(|e| FedimintError::InvalidRequest { msg: e.to_string() })?;
        
        let handled = self.state.clone().handle_rpc(
            request,
            CallbackWrapper(callback)
        );
        
        if let Some(task) = handled.task {
            self.runtime.spawn(task);
        }
        
        Ok(())
    }
}

struct CallbackWrapper(Box<dyn RpcCallback>);

impl RpcResponseHandler for CallbackWrapper {
    fn handle_response(&self, response: RpcResponse) {
        let json = serde_json::to_string(&response)
            .expect("Failed to serialize RPC response");
        self.0.on_response(json);
    }
}

fn create_database(path: &str, runtime: &tokio::runtime::Runtime) -> anyhow::Result<Database> {
    use fedimint_cursed_redb::MemAndRedb;
    
    std::fs::create_dir_all(path)?;
    
    let db_path = std::path::Path::new(path).join(DB_FILE_NAME);
    
        let locked_db = runtime.block_on(async { MemAndRedb::new(db_path).await })?;
    
    Ok(Database::new(locked_db, Default::default()))
}