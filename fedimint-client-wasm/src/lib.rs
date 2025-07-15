#![cfg(target_family = "wasm")]

use std::sync::Arc;

use fedimint_client_rpc::{RpcGlobalState, RpcRequest, RpcResponse, RpcResponseHandler};
use fedimint_core::db::Database;
use fedimint_cursed_redb::MemAndRedb;
use wasm_bindgen::prelude::{JsError, JsValue, wasm_bindgen};
use web_sys::FileSystemSyncAccessHandle;

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
    state: Arc<RpcGlobalState>,
}

#[wasm_bindgen]
impl RpcHandler {
    #[wasm_bindgen(constructor)]
    pub fn new(sync_handle: FileSystemSyncAccessHandle) -> Self {
        // Create the database directly
        let cursed_db = MemAndRedb::new(sync_handle).unwrap();
        let database = Database::new(cursed_db, Default::default());

        let state = Arc::new(RpcGlobalState::new(database));

        Self { state }
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
