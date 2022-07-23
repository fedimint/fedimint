use crate::consensus::FedimintConsensus;
use async_trait::async_trait;

use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::ApiError;
use fedimint_api::FederationModule;
use rand::CryptoRng;
use secp256k1_zkp::rand::RngCore;
use serde_json::Value;

pub struct FedimintInterconnet<'a, R: RngCore + CryptoRng> {
    pub fedimint: &'a FedimintConsensus<R>,
}

#[async_trait]
impl<'a, R> ModuleInterconect for FedimintInterconnet<'a, R>
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
            "wallet" => call_internal(&self.fedimint.wallet, path, data).await,
            "mint" => call_internal(&self.fedimint.mint, path, data).await,
            "ln" => call_internal(&self.fedimint.ln, path, data).await,
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
