use crate::consensus::MinimintConsensus;
use async_trait::async_trait;

use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::ApiError;
use minimint_api::FederationModule;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;
use serde_json::Value;

pub struct MinimintInterconnect<'a, R: RngCore + CryptoRng> {
    pub minimint: &'a MinimintConsensus<R>,
}

#[async_trait]
impl<'a, R> ModuleInterconect for MinimintInterconnect<'a, R>
where
    R: RngCore + CryptoRng,
{
    async fn call(
        &self,
        module: &'static str,
        path: String,
        data: Value,
    ) -> Result<Value, ApiError> {
        match module {
            "wallet" => call_internal(&self.minimint.wallet, path, data).await,
            "mint" => call_internal(&self.minimint.mint, path, data).await,
            "ln" => call_internal(&self.minimint.ln, path, data).await,
            _ => Err(ApiError::not_found(String::from("Module not found"))),
        }
    }
}

async fn call_internal<M: FederationModule + 'static>(
    module: &M,
    path: String,
    data: Value,
) -> Result<serde_json::Value, ApiError> {
    let endpoint = module
        .api_endpoints()
        .iter()
        .find(|endpoint| endpoint.path == path)
        .ok_or_else(|| ApiError::not_found(String::from("Method not found")))?;

    (endpoint.handler)(module, data).await
}
