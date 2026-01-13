use crate::DevimintdClient;

pub async fn test_shared() -> DevimintdClient {
    let _ = fedimint_logging::TracingSetup::default().init();
    DevimintdClient::shared()
}
