use std::net::SocketAddr;
use std::sync::Arc;

use fedimint_client_legacy::modules::ln::LightningGateway;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use ln_gateway::client::StandardGatewayClientBuilder;
use ln_gateway::lnrpc_client::ILnRpcClient;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::rpc_server::run_webserver;
use ln_gateway::rpc::ConnectFedPayload;
use ln_gateway::{Gateway, DEFAULT_FEES};
use tempfile::TempDir;
use url::Url;

use crate::federation::FederationTest;
use crate::fixtures::test_dir;

pub struct GatewayTest {
    api: Url,
    password: String,
    _config_dir: Option<TempDir>,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn get_rpc(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.api.clone(), self.password.clone())
    }

    /// Connects to a new federation and stores the info
    pub async fn connect_fed(&mut self, fed: &FederationTest) {
        let connect = fed.connection_code().to_string();
        let client = self.get_rpc().await;
        client
            .connect_federation(ConnectFedPayload { connect })
            .await
            .unwrap();
    }

    /// Returns the last registration we sent to a fed
    pub async fn last_registered(&self) -> LightningGateway {
        let info = self.get_rpc().await.get_info().await;
        let fed = info.expect("Failed to get_info").federations;
        fed.last().expect("No feds registered").registration.clone()
    }

    pub(crate) async fn new(
        base_port: u16,
        password: String,
        lightning: impl ILnRpcClient + 'static,
        decoders: ModuleDecoderRegistry,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: Url = format!("http://{listen}").parse().unwrap();
        let (path, _config_dir) = test_dir("gateway-cfg");

        // Create federation client builder for the gateway
        let client_builder: StandardGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path.clone());

        let gatewayd_db = Database::new(MemDatabase::new(), decoders.clone());
        let gateway = Gateway::new_with_lightning_connection(
            Arc::new(lightning),
            client_builder.clone(),
            DEFAULT_FEES,
            gatewayd_db,
            address.clone(),
        )
        .await
        .unwrap();

        run_webserver(password.clone(), listen, gateway)
            .await
            .expect("Failed to start webserver");

        Self {
            password,
            api: address,
            _config_dir,
        }
    }
}
