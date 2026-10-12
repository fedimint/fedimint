use std::time::Duration;

use fedimint_core::task::timeout;
use fedimint_gateway_server::IAdminGateway;
use fedimint_meta_client::api::MetaFederationApi;
use fedimint_meta_client::common::{DEFAULT_META_KEY, KIND, MetaValue};
use fedimint_meta_server::MetaInit;
use fedimint_testing_core::config::API_AUTH;

use super::fixtures;

#[tokio::test(flavor = "multi_thread")]
async fn gateway_reads_federation_name_from_meta_module() -> anyhow::Result<()> {
    timeout(Duration::from_secs(60), async {
        // Deliberately do not register a Meta client module: gateway metadata
        // lookup must work through its configured Meta source.
        let fixtures = fixtures().with_server_only_module(MetaInit);
        let fed = fixtures.new_fed_degraded().await;
        let client = fed.new_client().await;
        let config = client.config().await;
        assert!(config.global.federation_name().is_none());
        let (module_id, _) = config.get_first_module_by_kind_cfg(KIND)?;
        let value = MetaValue::from(br#"{"federation_name":"123"}"#.as_slice());
        for peer_id in fed.online_peer_ids() {
            fed.new_admin_api(peer_id)
                .await?
                .with_module(module_id)
                .submit(DEFAULT_META_KEY, value.clone(), API_AUTH.clone())
                .await?;
        }
        loop {
            if client
                .api()
                .with_module(module_id)
                .get_consensus(DEFAULT_META_KEY)
                .await?
                .is_some()
            {
                break;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }

        let gateway = fixtures.new_gateway().await;
        fed.connect_gateway(&gateway).await;
        // Joining and info reads do not wait for metadata; wait only in this
        // test for the independently populated cache.
        loop {
            let info = gateway.handle_get_info().await?;
            let federation = info
                .federations
                .iter()
                .find(|info| info.federation_id == fed.id())
                .expect("gateway should report the connected federation");
            if federation.federation_name.as_deref() == Some("123") {
                break;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
        anyhow::Ok(())
    })
    .await?
}
