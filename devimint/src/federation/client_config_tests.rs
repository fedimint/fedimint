use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_connectors::ConnectorRegistry;
use fedimint_core::PeerId;
use fedimint_core::config::{ClientConfig, GlobalClientConfig, PeerUrl};
use fedimint_core::endpoint_constants::CLIENT_CONFIG_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::CoreConsensusVersion;
use fedimint_core::util::SafeUrl;
use jsonrpsee::RpcModule;
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::types::ErrorObjectOwned;
use tokio::sync::Notify;

use super::await_client_config;

#[tokio::test]
async fn waits_for_consensus_api_after_invite_is_available() {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let url = SafeUrl::parse(&format!("ws://{}", server.local_addr().unwrap())).unwrap();
    let config = ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: BTreeMap::from([(
                PeerId::from(0),
                PeerUrl {
                    url: url.clone(),
                    name: "guardian".to_owned(),
                },
            )]),
            broadcast_public_keys: None,
            consensus_version: CoreConsensusVersion::new(0, 0),
            meta: BTreeMap::new(),
        },
        modules: BTreeMap::new(),
    };
    let invite = InviteCode::new(url, PeerId::from(0), config.calculate_federation_id(), None);
    let ready = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let retried = Arc::new(Notify::new());
    let mut module = RpcModule::new((ready.clone(), attempts.clone(), config, retried.clone()));
    module
        .register_method(CLIENT_CONFIG_ENDPOINT, |_, context, _| {
            if context.1.fetch_add(1, Ordering::SeqCst) == 15 {
                context.3.notify_one();
            }
            if context.0.load(Ordering::SeqCst) {
                Ok(context.2.clone())
            } else {
                Err(ErrorObjectOwned::owned(
                    -32601,
                    "Method not found",
                    None::<()>,
                ))
            }
        })
        .unwrap();
    let handle = server.start(module);
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await;
    let wait = await_client_config(&connectors, &invite);
    tokio::pin!(wait);

    // Outlast the fifteen fast attempts of download_from_invite_code without
    // relying on wall-clock timing or mutating the process-wide test env.
    tokio::select! {
        result = &mut wait => panic!("readiness finished before the API was ready: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(40), retried.notified()) => {
            result.expect("readiness should continue retrying");
        }
    }
    assert!(attempts.load(Ordering::SeqCst) >= 16);
    ready.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .expect("readiness should finish once the API serves a valid config")
        .expect("valid consensus config");
    handle.stop().unwrap();
    handle.stopped().await;
}
