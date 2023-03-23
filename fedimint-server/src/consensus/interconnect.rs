use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{ApiError, ApiRequestErased};
use serde_json::Value;

use crate::consensus::FedimintConsensus;

pub struct FedimintInterconnect<'a> {
    pub fedimint: &'a FedimintConsensus,
}

#[async_trait]
impl<'a> ModuleInterconect for FedimintInterconnect<'a> {
    async fn call(
        &self,
        id: ModuleInstanceId,
        path: String,
        data: ApiRequestErased,
    ) -> Result<Value, ApiError> {
        for (module_id, module) in self.fedimint.modules.iter_modules() {
            if module_id == id {
                let endpoint = module
                    .api_endpoints()
                    .into_iter()
                    .find(|endpoint| endpoint.path == path)
                    .ok_or_else(|| ApiError::not_found(String::from("Method not found")))?;

                return (endpoint.handler)(
                    module,
                    self.fedimint.db.begin_transaction().await,
                    data.to_json(),
                    Some(module_id),
                    self.fedimint.cfg.private.api_auth.clone(),
                )
                .await;
            }
        }
        panic!("Module not registered: {id}");
    }
}
