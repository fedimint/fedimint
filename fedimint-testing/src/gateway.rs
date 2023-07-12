use std::net::SocketAddr;
use std::sync::Arc;

use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::Client;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::client::StandardGatewayClientBuilder;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::rpc_server::run_webserver;
use ln_gateway::rpc::{ConnectFedPayload, FederationInfo};
use ln_gateway::Gateway;
use tempfile::TempDir;
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
    pub async fn remove_client(&self, fed: &FederationTest) -> Arc<Client> {
        self.gateway.remove_client(fed.id()).await.unwrap()
    }

    /// Connects to a new federation and stores the info
    pub async fn connect_fed(&mut self, fed: &FederationTest) -> FederationInfo {
        let connect = fed.connection_code().to_string();
        let rpc = self.get_rpc().await;
        rpc.connect_federation(ConnectFedPayload { connect })
            .await
            .unwrap()
    }

    pub fn get_gateway_public_key(&self) -> secp256k1::PublicKey {
        self.gateway.public_key
    }

    pub(crate) async fn new(
        base_port: u16,
        password: String,
        lightning: Arc<dyn LightningTest>,
        decoders: ModuleDecoderRegistry,
        registry: ClientModuleGenRegistry,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: Url = format!("http://{listen}").parse().unwrap();
        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: StandardGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path.clone(), registry, 0);

        let gatewayd_db = Database::new(MemDatabase::new(), decoders.clone());
        let gateway = Gateway::new_with_lightning_connection(
            lightning.as_rpc(),
            client_builder.clone(),
            RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            gatewayd_db,
            address.clone(),
        )
        .await
        .unwrap();

        run_webserver(password.clone(), listen, gateway.clone())
            .await
            .expect("Failed to start webserver");

        Self {
            password,
            api: address,
            _config_dir,
            gateway,
        }
    }
}
