use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fedimint_bitcoind::{DynBitcoindRpc, create_bitcoind};
use fedimint_client::module_init::{
    ClientModuleInitRegistry, DynClientModuleInit, IClientModuleInit,
};
use fedimint_core::config::{ModuleInitParams, ServerModuleConfigGenParamsRegistry};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::LightningMode;
use fedimint_gateway_server::Gateway;
use fedimint_gateway_server::client::GatewayClientBuilder;
use fedimint_gateway_server::config::LightningModuleMode;
use fedimint_lightning::{ILnRpcClient, LightningContext};
use fedimint_logging::TracingSetup;
use fedimint_server::core::{DynServerModuleInit, IServerModuleInit, ServerModuleInitRegistry};
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_bitcoin_rpc::esplora::EsploraClient;
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, IServerBitcoinRpc};
use fedimint_testing_core::test_dir;

use crate::btc::BitcoinTest;
use crate::btc::mock::FakeBitcoinFactory;
use crate::btc::real::RealBitcoinTest;
use crate::envs::{
    FM_PORT_ESPLORA_ENV, FM_TEST_BACKEND_BITCOIN_RPC_KIND_ENV, FM_TEST_BACKEND_BITCOIN_RPC_URL_ENV,
    FM_TEST_BITCOIND_RPC_ENV, FM_TEST_USE_REAL_DAEMONS_ENV,
};
use crate::federation::{FederationTest, FederationTestBuilder};
use crate::ln::FakeLightningTest;

/// A default timeout for things happening in tests
pub const TIMEOUT: Duration = Duration::from_secs(10);

pub const DEFAULT_GATEWAY_PASSWORD: &str = "thereisnosecondbest";

/// A tool for easily writing fedimint integration tests
pub struct Fixtures {
    clients: Vec<DynClientModuleInit>,
    servers: Vec<DynServerModuleInit>,
    params: ServerModuleConfigGenParamsRegistry,
    bitcoin_rpc: BitcoinRpcConfig,
    bitcoin: Arc<dyn BitcoinTest>,
    dyn_bitcoin_rpc: DynBitcoindRpc,
    bitcoin_rpc_connection: DynServerBitcoinRpc,
    primary_module_kind: ModuleKind,
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
        let (dyn_bitcoin_rpc, bitcoin, config, bitcoin_rpc_connection): (
            DynBitcoindRpc,
            Arc<dyn BitcoinTest>,
            BitcoinRpcConfig,
            DynServerBitcoinRpc,
        ) = if real_testing {
            // `backend-test.sh` overrides which Bitcoin RPC to use for electrs and esplora
            // backend tests
            let override_bitcoin_rpc_kind = env::var(FM_TEST_BACKEND_BITCOIN_RPC_KIND_ENV);
            let override_bitcoin_rpc_url = env::var(FM_TEST_BACKEND_BITCOIN_RPC_URL_ENV);

            let rpc_config = match (override_bitcoin_rpc_kind, override_bitcoin_rpc_url) {
                (Ok(kind), Ok(url)) => BitcoinRpcConfig {
                    kind: kind.parse().expect("must provide valid kind"),
                    url: url.parse().expect("must provide valid url"),
                },
                _ => BitcoinRpcConfig::get_defaults_from_env_vars()
                    .expect("must provide valid default env vars"),
            };

            let dyn_bitcoin_rpc = create_bitcoind(&rpc_config).unwrap();
            let bitcoincore_url = env::var(FM_TEST_BITCOIND_RPC_ENV)
                .expect("Must have bitcoind RPC defined for real tests")
                .parse()
                .expect("Invalid bitcoind RPC URL");
            let bitcoin = RealBitcoinTest::new(&bitcoincore_url, dyn_bitcoin_rpc.clone());

            let bitcoin_rpc_connection = match rpc_config.kind.as_ref() {
                "bitcoind" => BitcoindClient::new(&rpc_config.url, None)
                    .unwrap()
                    .into_dyn(),
                "esplora" => EsploraClient::new(&rpc_config.url).unwrap().into_dyn(),
                kind => panic!("Unknown bitcoin rpc kind {kind}"),
            };

            (
                dyn_bitcoin_rpc,
                Arc::new(bitcoin),
                rpc_config,
                bitcoin_rpc_connection,
            )
        } else {
            let FakeBitcoinFactory { bitcoin, config } = FakeBitcoinFactory::register_new();
            let dyn_bitcoin_rpc = DynBitcoindRpc::from(bitcoin.clone());

            let bitcoin_rpc_connection = bitcoin.clone().into_dyn();

            let bitcoin = Arc::new(bitcoin);

            (dyn_bitcoin_rpc, bitcoin, config, bitcoin_rpc_connection)
        };

        Self {
            clients: vec![],
            servers: vec![],
            params: ModuleRegistry::default(),
            bitcoin_rpc: config,
            bitcoin,
            dyn_bitcoin_rpc,
            bitcoin_rpc_connection,
            primary_module_kind: IClientModuleInit::module_kind(&client),
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

    /// Starts a new federation with 3/4 peers online
    pub async fn new_fed_degraded(&self) -> FederationTest {
        self.new_fed_builder(1).build().await
    }

    /// Starts a new federation with 4/4 peers online
    pub async fn new_fed_not_degraded(&self) -> FederationTest {
        self.new_fed_builder(0).build().await
    }

    /// Creates a new `FederationTestBuilder` that can be used to build up a
    /// `FederationTest` for module tests.
    pub fn new_fed_builder(&self, num_offline: u16) -> FederationTestBuilder {
        FederationTestBuilder::new(
            self.params.clone(),
            ServerModuleInitRegistry::from(self.servers.clone()),
            ClientModuleInitRegistry::from(self.clients.clone()),
            self.primary_module_kind.clone(),
            num_offline,
            self.bitcoin_rpc_connection(),
        )
    }

    /// Creates a new Gateway that can be used for module tests.
    pub async fn new_gateway(&self, lightning_module_mode: LightningModuleMode) -> Gateway {
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
            GatewayClientBuilder::new(path.clone(), registry, ModuleKind::from_static_str("dummy"));

        let ln_client: Arc<dyn ILnRpcClient> = Arc::new(FakeLightningTest::new());

        let (lightning_public_key, lightning_alias, lightning_network, _, _) = ln_client
            .parsed_node_info()
            .await
            .expect("Could not get Lightning info");
        let lightning_context = LightningContext {
            lnrpc: ln_client.clone(),
            lightning_public_key,
            lightning_alias,
            lightning_network,
        };

        // Module tests do not use the webserver, so any port is ok
        let listen: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let address: SafeUrl = format!("http://{listen}").parse().unwrap();

        Gateway::new_with_custom_registry(
            // Fixtures does not use real lightning connection, so just fake the connection
            // parameters
            LightningMode::Lnd {
                lnd_rpc_addr: "FakeRpcAddr".to_string(),
                lnd_tls_cert: "FakeTlsCert".to_string(),
                lnd_macaroon: "FakeMacaroon".to_string(),
            },
            client_builder,
            listen,
            address.clone(),
            bcrypt::HashParts::from_str(
                &bcrypt::hash(DEFAULT_GATEWAY_PASSWORD, bcrypt::DEFAULT_COST).unwrap(),
            )
            .unwrap(),
            bitcoin::Network::Regtest,
            0,
            gateway_db,
            // Manually set the gateway's state to `Running`. In tests, we do don't run the
            // webserver or intercept HTLCs, so this is necessary for instructing the
            // gateway that it is connected to the mock Lightning node.
            fedimint_gateway_server::GatewayState::Running { lightning_context },
            lightning_module_mode,
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

    pub fn bitcoin_rpc_connection(&self) -> DynServerBitcoinRpc {
        self.bitcoin_rpc_connection.clone()
    }
}
