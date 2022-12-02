use async_trait::async_trait;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::ApiError;
use serde_json::Value;

use crate::consensus::FedimintConsensus;

pub struct FedimintInterconnect<'a> {
    pub fedimint: &'a FedimintConsensus,
}

#[async_trait]
impl<'a> ModuleInterconect for FedimintInterconnect<'a> {
    async fn call(
        &self,
        module_name: &'static str,
        path: String,
        data: Value,
    ) -> Result<Value, ApiError> {
        for module in self.fedimint.modules.values() {
            if module.api_base_name() == module_name {
                let endpoint = module
                    .api_endpoints()
                    .into_iter()
                    .find(|endpoint| endpoint.path == path)
                    .ok_or_else(|| ApiError::not_found(String::from("Method not found")))?;

                return (endpoint.handler)(module, self.fedimint.database_transaction(), data)
                    .await;
            }
        }
        panic!("Module not registered: {}", module_name);
    }
}
