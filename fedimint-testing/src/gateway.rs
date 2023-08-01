use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::Client;
use fedimint_client_legacy::modules::ln::config::GatewayFee;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::client::StandardGatewayClientBuilder;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::rpc_server::run_webserver;
use ln_gateway::rpc::{ConnectFedPayload, FederationInfo};
use ln_gateway::Gateway;
use tempfile::TempDir;
use tokio::sync::RwLock;
use url::Url;

use crate::federation::FederationTest;
use crate::fixtures::test_dir;
use crate::ln::LightningTest;

/// Fixture for creating a gateway
pub struct GatewayTest {
    /// Password for the RPC
    pub password: String,
    /// URL for the RPC
    api: Url,
    /// Handle of the running gateway
    gateway: Gateway,
    /// Temporary dir that stores the gateway config
    _config_dir: Option<TempDir>,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn get_rpc(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.api.clone(), self.password.clone())
    }

    /// Removes a client from the gateway
    pub async fn remove_client(&self, fed: &FederationTest) -> Client {
        self.gateway.remove_client(fed.id()).await.unwrap()
    }

    pub async fn select_client(&self, federation_id: FederationId) -> Client {
        self.gateway.select_client(federation_id).await.unwrap()
    }

    /// Connects to a new federation and stores the info
    pub async fn connect_fed(&mut self, fed: &FederationTest) -> FederationInfo {
        let connect = fed.connection_code().to_string();
        let rpc = self.get_rpc().await;
        rpc.connect_federation(ConnectFedPayload { connect })
            .await
            .unwrap()
    }

    pub fn get_gateway_id(&self) -> secp256k1::PublicKey {
        self.gateway.gateway_id
    }

    pub(crate) async fn new(
        base_port: u16,
        password: String,
        lightning: Box<dyn LightningTest>,
        decoders: ModuleDecoderRegistry,
        registry: ClientModuleGenRegistry,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: Url = format!("http://{listen}").parse().unwrap();
        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: StandardGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path.clone(), registry, 0);

        let mut tg = TaskGroup::new();
        // Create the stream to route HTLCs. We cannot create the Gateway until the
        // stream to the lightning node has been setup.
        let (stream, ln_client) = lightning.route_htlcs(&mut tg).await.unwrap();

        let clients = Arc::new(RwLock::new(BTreeMap::new()));
        let scid_to_federation = Arc::new(RwLock::new(BTreeMap::new()));

        // Create gateway with the client created from `route_htlcs`
        let gateway = Gateway::new(
            ln_client.clone(),
            client_builder.clone(),
            GatewayFee(RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            })
            .0,
            Database::new(MemDatabase::new(), decoders.clone()),
            address.clone(),
            clients.clone(),
            scid_to_federation.clone(),
            tg.clone(),
        )
        .await
        .unwrap();

        run_webserver(password.clone(), listen, gateway.clone())
            .await
            .expect("Failed to start webserver");

        // Spawn new thread to listen for HTLCs
        tg.spawn("Subscribe to intercepted HTLCs", move |handle| async move {
            Gateway::handle_htlc_stream(stream, ln_client, handle, scid_to_federation, clients)
                .await;
        })
        .await;

        Self {
            password,
            api: address,
            _config_dir,
            gateway,
        }
    }
}
