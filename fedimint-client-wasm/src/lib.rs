#![cfg(target_family = "wasm")]

use std::sync::Arc;

use fedimint_client_rpc::{RpcGlobalState, RpcRequest, RpcResponse, RpcResponseHandler};
use fedimint_core::db::Database;
use fedimint_cursed_redb::MemAndRedb;
use wasm_bindgen::prelude::{JsError, JsValue, wasm_bindgen};
use web_sys::FileSystemSyncAccessHandle;

/// Runs automatically when the wasm module is instantiated, before any
/// exported function can be called; calling it again is harmless.
///
/// Without a hook, a panic anywhere in the module (including the RPC tasks
/// spawned via `wasm_bindgen_futures::spawn_local`) traps with a message-less
/// `RuntimeError: unreachable executed` and the panic message and Rust
/// location are lost. Log them to the console instead.
///
/// When triaging, trust the first logged panic: after it, the executor's
/// poisoned state may log an unrelated `BorrowMutError` panic as well.
#[wasm_bindgen(start)]
fn install_panic_hook() {
    console_error_panic_hook::set_once();
}

struct JsFunctionWrapper(js_sys::Function);

impl RpcResponseHandler for JsFunctionWrapper {
    fn handle_response(&self, response: RpcResponse) {
        let response = serde_json::to_string(&response).expect(
            "RpcResponse is numbers, strings and serde_json::Value; serialization cannot fail",
        );
        if let Err(err) = self
            .0
            .call1(&JsValue::null(), &JsValue::from_str(&response))
        {
            // There is no tracing subscriber in the wasm client, so log
            // straight to the console; swallowing this leaves the request
            // hanging with zero diagnostics.
            web_sys::console::error_2(&JsValue::from_str("RPC response callback threw"), &err);
        }
    }
}

#[wasm_bindgen]
struct RpcHandler {
    state: Arc<RpcGlobalState>,
}

#[wasm_bindgen]
impl RpcHandler {
    #[wasm_bindgen(constructor)]
    pub async fn new(sync_handle: FileSystemSyncAccessHandle) -> Result<RpcHandler, JsError> {
        // Return errors instead of panicking: a panic in an async export
        // leaves the returned `Promise` unsettled forever, so the caller
        // would hang instead of getting a rejection it can catch.
        let cursed_db = MemAndRedb::new(sync_handle)
            .map_err(|err| JsError::new(&format!("Failed to open client database: {err:#}")))?;
        let database = Database::new(cursed_db, Default::default());
        let connectors = fedimint_connectors::ConnectorRegistry::build_from_client_defaults()
            .bind()
            .await;

        let state = Arc::new(RpcGlobalState::new(connectors, database));

        Ok(Self { state })
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
