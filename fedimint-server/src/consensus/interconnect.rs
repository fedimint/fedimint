use async_trait::async_trait;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::ApiError;
use fedimint_api::ServerModulePlugin;
use serde_json::Value;

use crate::consensus::FedimintConsensus;

pub struct FedimintInterconnect<'a> {
    pub fedimint: &'a FedimintConsensus,
}

#[async_trait]
impl<'a> ModuleInterconect for FedimintInterconnect<'a> {
    async fn call(
        &self,
        module: &'static str,
        path: String,
        data: Value,
    ) -> Result<Value, ApiError> {
        match module {
            "wallet" => call_internal(&self.fedimint.wallet, path, data).await,
            "mint" => call_internal(&self.fedimint.mint, path, data).await,
            "ln" => call_internal(&self.fedimint.ln, path, data).await,
            _ => Err(ApiError::not_found(String::from("Module not found"))),
        }
    }
}

async fn call_internal<M: ServerModulePlugin + 'static>(
    module: &M,
    path: String,
    data: Value,
) -> Result<serde_json::Value, ApiError> {
    let endpoint = module
        .api_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.path == path)
        .ok_or_else(|| ApiError::not_found(String::from("Method not found")))?;

    (endpoint.handler)(module, data).await
}
