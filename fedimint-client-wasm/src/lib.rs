use std::{str::FromStr, sync::Arc};

use fedimint_client::{
    client_rpc,
    secret::{PlainRootSecretStrategy, RootSecretStrategy},
    ClientHandleArc,
};
use fedimint_core::{invite_code::InviteCode, secp256k1::rand::thread_rng};
use fedimint_ln_client::{LightningClientInit, LightningClientModule};
use fedimint_mint_client::{MintClientInit, MintClientModule};
use futures::StreamExt;
use serde_json::json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmClient {
    client: ClientHandleArc,
    rpc_server: client_rpc::Server<Self>,
}

impl AsRef<LightningClientModule> for WasmClient {
    fn as_ref(&self) -> &LightningClientModule {
        self.client.get_first_module().module
    }
}

impl AsRef<MintClientModule> for WasmClient {
    fn as_ref(&self) -> &MintClientModule {
        self.client.get_first_module().module
    }
}

impl AsRef<fedimint_client::Client> for WasmClient {
    fn as_ref(&self) -> &fedimint_client::Client {
        &self.client
    }
}

#[wasm_bindgen]
impl WasmClient {
    #[wasm_bindgen]
    pub async fn open() -> Result<Option<WasmClient>, JsError> {
        Ok(None)
    }

    #[wasm_bindgen]
    pub async fn join_federation(invite_code: String) -> Result<WasmClient, JsError> {
        Self::join_federation_inner(invite_code)
            .await
            .map_err(|x| JsError::new(&x.to_string()))
    }

    async fn join_federation_inner(invite_code: String) -> anyhow::Result<WasmClient> {
        let db = fedimint_core::db::mem_impl::MemDatabase::new();
        let secret = fedimint_client::secret::PlainRootSecretStrategy::random(&mut thread_rng());
        let root_secret = PlainRootSecretStrategy::to_root_secret(&secret);
        let mut builder = fedimint_client::Client::builder(db.into());
        builder.with_module(MintClientInit);
        builder.with_module(LightningClientInit::default());
        builder.with_primary_module(1);
        let invite_code = InviteCode::from_str(&invite_code)?;
        let config = fedimint_api_client::download_from_invite_code(&invite_code).await?;
        let client = Arc::new(builder.join(root_secret, config, None).await?);
        let mut rpc_server = client_rpc::Server::new();
        rpc_server.add_handler(fedimint_ln_client::PayBolt11InvoiceRpc);
        rpc_server.add_handler(fedimint_mint_client::MintReissueExternalNotesRpc);
        rpc_server.add_handler(fedimint_client::client_rpc::ClientBalanceRpc);
        Ok(Self { client, rpc_server })
    }

    #[wasm_bindgen]
    pub async fn rpc(&self, module: &str, method: &str, body: String, cb: &js_sys::Function) {
        let json = serde_json::from_str(&body).unwrap();
        let mut stream = self.rpc_server.handle_request(self, module, method, json);
        while let Some(item) = stream.next().await {
            let this = JsValue::null();
            let _ = match item {
                Ok(item) => cb.call1(
                    &this,
                    &JsValue::from_str(&serde_json::to_string(&item).unwrap()),
                ),
                Err(err) => cb.call1(
                    &this,
                    &JsValue::from_str(
                        &serde_json::to_string(&json!({"error": err.to_string()})).unwrap(),
                    ),
                ),
            };
        }
    }
}
