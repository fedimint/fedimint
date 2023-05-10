use std::net::SocketAddr;
use std::sync::Arc;

use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use ln_gateway::client::{DynGatewayClientBuilder, MemDbFactory, StandardGatewayClientBuilder};
use ln_gateway::lnrpc_client::ILnRpcClient;
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::ConnectFedPayload;
use ln_gateway::Gateway;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tracing::log::warn;
use url::Url;

use crate::federation::FederationTest;
use crate::fixtures::test_dir;

pub struct GatewayTest {
    password: String,
    address: Url,
    _config_dir: Option<TempDir>,
    _task: TaskGroup,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn new_client(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.address.clone(), self.password.clone())
    }

    pub async fn connect_fed(&self, fed: &FederationTest) {
        let connect = fed.connection_code().to_string();
        let client = self.new_client().await;
        client
            .connect_federation(ConnectFedPayload { connect })
            .await
            .unwrap();
    }

    pub(crate) async fn new(
        base_port: u16,
        lightning: impl ILnRpcClient + 'static,
        decoders: ModuleDecoderRegistry,
        module_gens: ClientModuleGenRegistry,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: Url = format!("http://{listen}").parse().unwrap();
        let mut task = TaskGroup::new();
        let password = rand::random::<u64>().to_string();
        let (path, _config_dir) = test_dir("gateway-cfg");

        // Create federation client builder for the gateway
        let client_builder: DynGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path, MemDbFactory.into(), address.clone()).into();

        let gateway = Gateway::new_with_lightning_connection(
            Arc::new(RwLock::new(lightning)),
            client_builder.clone(),
            decoders.clone(),
            module_gens.clone(),
            task.make_subgroup().await,
        )
        .await
        .unwrap();

        gateway.spawn_webserver(listen, password.clone()).await;
        task.spawn("gatewayd", move |handle| async {
            if let Err(err) = gateway.run(handle).await {
                warn!("Gateway stopped with error {:?}", err);
            }
        })
        .await;

        Self {
            password,
            address,
            _config_dir,
            _task: task,
        }
    }
}
