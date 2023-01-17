use std::collections::BTreeSet;
use std::sync::Arc;

use fedimint_api::core::ModuleInstanceId;
use fedimint_api::PeerId;
use fedimint_ln::LightningGateway;
use mint_client::api::fake::FederationApiFaker;
use tokio::sync::Mutex;

#[derive(Debug, Default)]
pub struct MockApi {
    gateway: Option<LightningGateway>,
}

impl MockApi {
    pub async fn make_test_fed(
        module_id: ModuleInstanceId,
        members: BTreeSet<PeerId>,
    ) -> FederationApiFaker<tokio::sync::Mutex<MockApi>> {
        FederationApiFaker::new(Arc::new(Mutex::new(MockApi::default())), members)
            .with(
                format!("/module/{}/register_gateway", module_id),
                |mint: Arc<Mutex<MockApi>>, gateway: LightningGateway| async move {
                    mint.lock().await.gateway = Some(gateway);
                    Ok(())
                },
            )
            .with(
                format!("/module/{}/list_gateways", module_id),
                |mint: Arc<Mutex<MockApi>>, _: ()| async move {
                    Ok(mint
                        .lock()
                        .await
                        .gateway
                        .clone()
                        .into_iter()
                        .collect::<Vec<LightningGateway>>())
                },
            )
    }
}
