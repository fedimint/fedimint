#![cfg(target_family = "wasm")]
use std::str::FromStr;
use std::sync::Arc;

use fedimint_client_rpc::{
    DatabaseFactory, RpcGlobalState, RpcRequest, RpcResponse, RpcResponseHandler,
};
use fedimint_core::db::Database;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_indexeddb::MemAndIndexedDb;
use serde_json::json;
use wasm_bindgen::prelude::{JsError, JsValue, wasm_bindgen};

struct MemAndIndexedDbLoader;

#[apply(async_trait_maybe_send)]
impl DatabaseFactory for MemAndIndexedDbLoader {
    async fn create_database(&self, name: &str) -> anyhow::Result<Database> {
        Ok(Database::from(MemAndIndexedDb::new(name).await?))
    }
}

struct JsFunctionWrapper(js_sys::Function);

impl RpcResponseHandler for JsFunctionWrapper {
    fn handle_response(&self, response: RpcResponse) {
        let _ = self.0.call1(
            &JsValue::null(),
            &JsValue::from_str(&serde_json::to_string(&response).unwrap()),
        );
    }
}

#[wasm_bindgen]
struct RpcHandler {
    state: Arc<RpcGlobalState<MemAndIndexedDbLoader>>,
}

#[wasm_bindgen]
impl RpcHandler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            state: Arc::new(RpcGlobalState::new(MemAndIndexedDbLoader)),
        }
    }

    #[wasm_bindgen]
    pub fn rpc(&self, request: String, cb: js_sys::Function) -> Result<(), JsError> {
        let request: RpcRequest = serde_json::from_str(&request)
            .map_err(|e| JsError::new(&format!("Failed to parse request: {}", e)))?;

        let handled = self
            .state
            .clone()
            .handle_rpc(request, JsFunctionWrapper(cb));

        if let Some(task) = handled.task {
            wasm_bindgen_futures::spawn_local(task);
        }
        Ok(())
    }
}
