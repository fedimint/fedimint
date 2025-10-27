use async_trait::async_trait;
use fedimint_gateway_common::GatewayInfo;

#[async_trait]
pub trait IAdminGateway {
    type Error;

    async fn handle_get_info(&self) -> Result<GatewayInfo, Self::Error>;
}
