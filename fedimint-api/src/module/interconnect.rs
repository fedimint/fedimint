use async_trait::async_trait;

use super::ApiError;

/// Provides an interface to call APIs of other modules
#[async_trait(?Send)]
pub trait ModuleInterconect: Sync + Send {
    /// Simulates a call to an API endpoint of another module.
    /// This has lower latency.
    async fn call(
        &self,
        module: &'static str,
        path: String,
        data: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError>;
}
