use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::Client;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use lightning::routing::gossip::RoutingFees;
use ln_gateway::client::StandardGatewayClientBuilder;
use ln_gateway::lnrpc_client::{ILnRpcClient, LightningBuilder};
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{ConnectFedPayload, FederationInfo};
use ln_gateway::{Gateway, GatewayState};
use secp256k1::PublicKey;
use tempfile::TempDir;

use crate::federation::FederationTest;
use crate::fixtures::{test_dir, Fixtures};
use crate::ln::mock::FakeLightningTest;
use crate::ln::real::{ClnLightningTest, LndLightningTest};
use crate::ln::LightningTest;

pub const DEFAULT_GATEWAY_PASSWORD: &str = "thereisnosecondbest";

/// Fixture for creating a gateway
pub struct GatewayTest {
    /// URL for the RPC
    api: SafeUrl,
    /// Handle of the running gateway
    pub gateway: Gateway,
    /// Temporary dir that stores the gateway config
    _config_dir: Option<TempDir>,
    // Public key of the lightning node
    pub node_pub_key: PublicKey,
    // Listening address of the lightning node
    pub listening_addr: String,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn get_rpc(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.api.clone(), None)
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
        let invite_code = fed.invite_code().to_string();
        let rpc = self
            .get_rpc()
            .await
            .with_password(Some(DEFAULT_GATEWAY_PASSWORD.to_string()));
        rpc.connect_federation(ConnectFedPayload { invite_code })
            .await
            .unwrap()
    }

    pub fn get_gateway_id(&self) -> secp256k1::PublicKey {
        self.gateway.gateway_id
    }

    pub(crate) async fn new(
        base_port: u16,
        cli_password: Option<String>,
        lightning: Box<dyn LightningTest>,
        decoders: ModuleDecoderRegistry,
        registry: ClientModuleInitRegistry,
        num_route_hints: usize,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: SafeUrl = format!("http://{listen}").parse().unwrap();
        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: StandardGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path.clone(), registry, 0);

        let lightning_builder: Arc<dyn LightningBuilder + Send + Sync> = if Fixtures::is_real_test()
        {
            Arc::new(RealLightningBuilder {
                node_type: lightning.lightning_node_type(),
            })
        } else {
            Arc::new(FakeLightningBuilder {})
        };

        let gateway_db = Database::new(MemDatabase::new(), decoders.clone());

        let gateway = Gateway::new_with_custom_registry(
            lightning_builder,
            client_builder,
            listen,
            address.clone(),
            cli_password,
            RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            num_route_hints,
            gateway_db,
        )
        .await
        .expect("Failed to create gateway");

        let mut task_group = TaskGroup::new();
        let gateway_run = gateway.clone();
        task_group
            .spawn("Gateway Run", |_handle| async move {
                gateway_run.run().await.expect("Failed to start gateway");
            })
            .await;

        // Wait for the gateway to be in the configuring or running state
        GatewayTest::wait_for_gateway_state(gateway.clone(), |gw_state| {
            matches!(gw_state, GatewayState::Configuring)
                || matches!(gw_state, GatewayState::Running { .. })
        })
        .await;

        let listening_addr = lightning.listening_address();
        let info = lightning.info().await.unwrap();

        Self {
            api: address,
            _config_dir,
            gateway,
            node_pub_key: PublicKey::from_slice(info.pub_key.as_slice()).unwrap(),
            listening_addr,
        }
    }

    pub async fn wait_for_gateway_state(gateway: Gateway, func: impl Fn(GatewayState) -> bool) {
        let mut gateway_state_iterations = 0;
        loop {
            let gw_state = gateway.state.read().await.clone();
            if func(gw_state) {
                break;
            }

            if gateway_state_iterations >= 30 {
                panic!("Gateway did not start running after 10 attempts");
            }

            gateway_state_iterations += 1;
            sleep(Duration::from_secs(1)).await;
        }
    }
}

#[derive(Debug, Clone)]
pub enum LightningNodeType {
    Cln,
    Lnd,
    Ldk,
}

impl Display for LightningNodeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeType::Cln => write!(f, "cln"),
            LightningNodeType::Lnd => write!(f, "lnd"),
            LightningNodeType::Ldk => write!(f, "ldk"),
        }
    }
}

#[derive(Clone)]
pub struct RealLightningBuilder {
    node_type: LightningNodeType,
}

#[async_trait]
impl LightningBuilder for RealLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        match &self.node_type {
            LightningNodeType::Cln => Box::new(ClnLightningTest::new().await),
            LightningNodeType::Lnd => Box::new(LndLightningTest::new().await),
            _ => {
                unimplemented!("Unsupported Lightning implementation");
            }
        }
    }
}

#[derive(Clone)]
pub struct FakeLightningBuilder;

#[async_trait]
impl LightningBuilder for FakeLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        Box::new(FakeLightningTest::new())
    }
}
