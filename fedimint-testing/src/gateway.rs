use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_client::module::init::ClientModuleInitRegistry;
use fedimint_client::ClientArc;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{block_in_place, sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_TEST;
use futures::executor::block_on;
use lightning_invoice::RoutingFees;
use ln_gateway::client::GatewayClientBuilder;
use ln_gateway::lnrpc_client::{ILnRpcClient, LightningBuilder};
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::{ConnectFedPayload, FederationConnectionInfo};
use ln_gateway::{Gateway, GatewayState};
use secp256k1::PublicKey;
use tempfile::TempDir;
use tracing::{info, warn};

use crate::federation::FederationTest;
use crate::fixtures::{test_dir, Fixtures};
use crate::ln::mock::FakeLightningTest;
use crate::ln::real::{ClnLightningTest, LndLightningTest};
use crate::ln::LightningTest;

pub const DEFAULT_GATEWAY_PASSWORD: &str = "thereisnosecondbest";

/// Fixture for creating a gateway
pub struct GatewayTest {
    /// URL for the RPC
    versioned_api: SafeUrl,
    /// Handle of the running gateway
    pub gateway: Gateway,
    /// Temporary dir that stores the gateway config
    _config_dir: Option<TempDir>,
    // Public key of the lightning node
    pub node_pub_key: PublicKey,
    // Listening address of the lightning node
    pub listening_addr: String,
    /// `TaskGroup` that is running the test
    task_group: TaskGroup,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn get_rpc(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.versioned_api.clone(), None)
    }

    /// Removes a client from the gateway
    pub async fn remove_client(&self, fed: &FederationTest) -> ClientArc {
        self.gateway.remove_client(fed.id()).await.unwrap()
    }

    pub async fn select_client(&self, federation_id: FederationId) -> ClientArc {
        self.gateway.select_client(federation_id).await.unwrap()
    }

    /// Connects to a new federation and stores the info
    pub async fn connect_fed(&mut self, fed: &FederationTest) -> FederationConnectionInfo {
        info!(target: LOG_TEST, "Sending rpc to connect gateway to federation");
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
        num_route_hints: u32,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: SafeUrl = format!("http://{listen}").parse().unwrap();
        let versioned_api = address.join("v1").unwrap();

        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: GatewayClientBuilder =
            GatewayClientBuilder::new(path.clone(), registry, 0);

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
            cli_password.clone(),
            None, // Use default Network which is "regtest"
            RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            num_route_hints,
            gateway_db,
        )
        .await
        .expect("Failed to create gateway");

        let gateway_run = gateway.clone();
        let mut root_group = TaskGroup::new();
        let mut tg = root_group.clone();
        root_group
            .spawn("Gateway Run", |_handle| async move {
                gateway_run
                    .run(&mut tg)
                    .await
                    .expect("Failed to start gateway");
            })
            .await;

        // Wait for the gateway web server to be available
        GatewayTest::wait_for_webserver(versioned_api.clone(), cli_password)
            .await
            .expect("Gateway web server failed to start");

        // Wait for the gateway to be in the configuring or running state
        GatewayTest::wait_for_gateway_state(gateway.clone(), |gw_state| {
            matches!(gw_state, GatewayState::Configuring)
                || matches!(gw_state, GatewayState::Running { .. })
        })
        .await
        .expect("Gateway failed to start");

        let listening_addr = lightning.listening_address();
        let info = lightning.info().await.unwrap();

        Self {
            versioned_api,
            _config_dir,
            gateway,
            node_pub_key: PublicKey::from_slice(info.pub_key.as_slice()).unwrap(),
            listening_addr,
            task_group: root_group,
        }
    }

    pub async fn wait_for_webserver(
        versioned_api: SafeUrl,
        password: Option<String>,
    ) -> anyhow::Result<()> {
        let rpc = GatewayRpcClient::new(versioned_api, password);
        for _ in 0..30 {
            let rpc_result = rpc.get_info().await;
            if rpc_result.is_ok() {
                return Ok(());
            }

            sleep(Duration::from_secs(1)).await;
        }

        Err(anyhow!(
            "Gateway web server did not come up within 30 seconds"
        ))
    }

    pub async fn wait_for_gateway_state(
        gateway: Gateway,
        func: impl Fn(GatewayState) -> bool,
    ) -> anyhow::Result<()> {
        for _ in 0..30 {
            let gw_state = gateway.state.read().await.clone();
            if func(gw_state) {
                return Ok(());
            }

            sleep(Duration::from_secs(1)).await;
        }

        Err(anyhow!(
            "Gateway did not reach desired state within 30 seconds"
        ))
    }
}

impl Drop for GatewayTest {
    fn drop(&mut self) {
        block_in_place(move || {
            block_on(async move {
                if let Err(e) = self.task_group.clone().shutdown_join_all(None).await {
                    warn!("Got error shutting down GatewayTest: {e:?}")
                }
            })
        });
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
