use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_client::module::init::{
    ClientModuleInitRegistry, DynClientModuleInit, IClientModuleInit,
};
use fedimint_core::config::{
    ModuleInitParams, ServerModuleConfigGenParamsRegistry, ServerModuleInitRegistry,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{DynServerModuleInit, IServerModuleInit};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_logging::TracingSetup;
use fedimint_testing_core::test_dir;
use lightning_invoice::RoutingFees;
use ln_gateway::client::GatewayClientBuilder;
use ln_gateway::lightning::{ILnRpcClient, LightningBuilder};
use ln_gateway::{Gateway, LightningContext};

use crate::btc::mock::FakeBitcoinFactory;
use crate::btc::real::RealBitcoinTest;
use crate::btc::BitcoinTest;
use crate::envs::{FM_PORT_ESPLORA_ENV, FM_TEST_BITCOIND_RPC_ENV, FM_TEST_USE_REAL_DAEMONS_ENV};
use crate::federation::{FederationTest, FederationTestBuilder};
use crate::gateway::{FakeLightningBuilder, DEFAULT_GATEWAY_PASSWORD};

/// A default timeout for things happening in tests
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// A tool for easily writing fedimint integration tests
pub struct Fixtures {
    clients: Vec<DynClientModuleInit>,
    servers: Vec<DynServerModuleInit>,
    params: ServerModuleConfigGenParamsRegistry,
    bitcoin_rpc: BitcoinRpcConfig,
    bitcoin: Arc<dyn BitcoinTest>,
    dyn_bitcoin_rpc: DynBitcoindRpc,
    id: ModuleInstanceId,
}

impl Fixtures {
    pub fn new_primary(
        client: impl IClientModuleInit + 'static,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
        params: impl ModuleInitParams,
    ) -> Self {
        // Ensure tracing has been set once
        let _ = TracingSetup::default().init();
        let real_testing = Fixtures::is_real_test();
        let task_group = TaskGroup::new();
        let (dyn_bitcoin_rpc, bitcoin, config): (
            DynBitcoindRpc,
            Arc<dyn BitcoinTest>,
            BitcoinRpcConfig,
        ) = if real_testing {
            let rpc_config = BitcoinRpcConfig::get_defaults_from_env_vars().unwrap();
            let dyn_bitcoin_rpc = create_bitcoind(&rpc_config, task_group.make_handle()).unwrap();
            let bitcoincore_url = env::var(FM_TEST_BITCOIND_RPC_ENV)
                .expect("Must have bitcoind RPC defined for real tests")
                .parse()
                .expect("Invalid bitcoind RPC URL");
            let bitcoin = RealBitcoinTest::new(&bitcoincore_url, dyn_bitcoin_rpc.clone());
            (dyn_bitcoin_rpc, Arc::new(bitcoin), rpc_config)
        } else {
            let FakeBitcoinFactory { bitcoin, config } = FakeBitcoinFactory::register_new();
            let dyn_bitcoin_rpc = DynBitcoindRpc::from(bitcoin.clone());
            let bitcoin = Arc::new(bitcoin);
            (dyn_bitcoin_rpc, bitcoin, config)
        };

        Self {
            clients: vec![],
            servers: vec![],
            params: ModuleRegistry::default(),
            bitcoin_rpc: config,
            bitcoin,
            dyn_bitcoin_rpc,
            id: 0,
        }
        .with_module(client, server, params)
    }

    pub fn is_real_test() -> bool {
        env::var(FM_TEST_USE_REAL_DAEMONS_ENV) == Ok("1".to_string())
    }

    // TODO: Auto-assign instance ids after removing legacy id order
    /// Add a module to the fed
    pub fn with_module(
        mut self,
        client: impl IClientModuleInit + 'static,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
        params: impl ModuleInitParams,
    ) -> Self {
        self.params
            .attach_config_gen_params_by_id(self.id, server.module_kind(), params);
        self.clients.push(DynClientModuleInit::from(client));
        self.servers.push(DynServerModuleInit::from(server));
        self.id += 1;

        self
    }

    pub fn with_server_only_module(
        mut self,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
        params: impl ModuleInitParams,
    ) -> Self {
        self.params
            .attach_config_gen_params_by_id(self.id, server.module_kind(), params);
        self.servers.push(DynServerModuleInit::from(server));
        self.id += 1;

        self
    }

    /// Starts a new federation with default number of peers for testing
    pub async fn new_default_fed(&self) -> FederationTest {
        self.new_fed_builder().build().await
    }

    /// Creates a new `FederationTestBuilder` that can be used to build up a
    /// `FederationTest` for module tests.
    pub fn new_fed_builder(&self) -> FederationTestBuilder {
        FederationTestBuilder::new(
            self.params.clone(),
            ServerModuleInitRegistry::from(self.servers.clone()),
            ClientModuleInitRegistry::from(self.clients.clone()),
        )
    }

    /// Creates a new Gateway that can be used for module tests.
    pub async fn new_gateway(&self) -> Gateway {
        let server_gens = ServerModuleInitRegistry::from(self.servers.clone());
        let module_kinds = self.params.iter_modules().map(|(id, kind, _)| (id, kind));
        let decoders = server_gens.available_decoders(module_kinds).unwrap();
        let gateway_db = Database::new(MemDatabase::new(), decoders.clone());
        let clients = self.clients.clone().into_iter();

        let registry = clients
            .filter(|client| {
                // Remove LN module because the gateway adds one
                client.to_dyn_common().module_kind() != ModuleKind::from_static_str("ln")
            })
            .filter(|client| {
                // Remove LN NG module because the gateway adds one
                client.to_dyn_common().module_kind() != ModuleKind::from_static_str("lnv2")
            })
            .collect();

        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: GatewayClientBuilder =
            GatewayClientBuilder::new(path.clone(), registry, 0);

        let lightning_builder: Arc<dyn LightningBuilder + Send + Sync> =
            Arc::new(FakeLightningBuilder);

        // Module tests do not use the webserver, so any port is ok
        let listen: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let address: SafeUrl = format!("http://{listen}").parse().unwrap();

        let ln_client: Arc<dyn ILnRpcClient> = lightning_builder.build().await.into();
        let (lightning_public_key, lightning_alias, lightning_network, _, _) = ln_client
            .parsed_node_info()
            .await
            .expect("Could not get Lighytning info");
        let lightning_context = LightningContext {
            lnrpc: ln_client.clone(),
            lightning_public_key,
            lightning_alias,
            lightning_network,
        };

        Gateway::new_with_custom_registry(
            lightning_builder,
            client_builder,
            listen,
            address.clone(),
            Some(DEFAULT_GATEWAY_PASSWORD.to_string()),
            Some(bitcoin::Network::Regtest),
            RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            0,
            gateway_db,
            // Manually set the gateway's state to `Running`. In tests, we do don't run the
            // webserver or intercept HTLCs, so this is necessary for instructing the
            // gateway that it is connected to the mock Lightning node.
            ln_gateway::GatewayState::Running { lightning_context },
        )
        .await
        .expect("Failed to create gateway")
    }

    /// Get a server bitcoin RPC config
    pub fn bitcoin_server(&self) -> BitcoinRpcConfig {
        self.bitcoin_rpc.clone()
    }

    /// Get a client bitcoin RPC config
    // TODO: Right now we only support mocks or esplora, we should support others in
    // the future
    pub fn bitcoin_client(&self) -> BitcoinRpcConfig {
        if Fixtures::is_real_test() {
            BitcoinRpcConfig {
                kind: "esplora".to_string(),
                url: SafeUrl::parse(&format!(
                    "http://127.0.0.1:{}/",
                    env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
                ))
                .expect("Failed to parse default esplora server"),
            }
        } else {
            self.bitcoin_rpc.clone()
        }
    }

    /// Get a test bitcoin fixture
    pub fn bitcoin(&self) -> Arc<dyn BitcoinTest> {
        self.bitcoin.clone()
    }

    pub fn dyn_bitcoin_rpc(&self) -> DynBitcoindRpc {
        self.dyn_bitcoin_rpc.clone()
    }
}
