use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fedimint_bip39::Bip39RootSecretStrategy;
use fedimint_bitcoind::{BitcoindTracked, DynBitcoindRpc, IBitcoindRpc, create_esplora_rpc};
use fedimint_client::Client;
use fedimint_client::module_init::{
    ClientModuleInitRegistry, DynClientModuleInit, IClientModuleInit,
};
use fedimint_client::secret::RootSecretStrategy;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{ChainSource, LightningInfo, LightningMode};
use fedimint_gateway_server::Gateway;
use fedimint_gateway_server::client::GatewayClientBuilder;
use fedimint_gateway_server::config::DatabaseBackend;
use fedimint_lightning::{ILnRpcClient, LightningContext};
use fedimint_logging::TracingSetup;
use fedimint_server::core::{DynServerModuleInit, IServerModuleInit, ServerModuleInitRegistry};
use fedimint_server_bitcoin_rpc::bitcoind::BitcoindClient;
use fedimint_server_bitcoin_rpc::esplora::EsploraClient;
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, IServerBitcoinRpc};
use fedimint_testing_core::test_dir;
use rand::rngs::OsRng;

use crate::btc::BitcoinTest;
use crate::btc::mock::FakeBitcoinTest;
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
    clients: ClientModuleInitRegistry,
    servers: ServerModuleInitRegistry,
    bitcoin_rpc: BitcoinRpcConfig,
    bitcoin: Arc<dyn BitcoinTest>,
    fake_bitcoin_rpc: Option<DynBitcoindRpc>,
    server_bitcoin_rpc: DynServerBitcoinRpc,
    primary_module_kind: ModuleKind,
}

impl Fixtures {
    pub fn new_primary(
        client: impl IClientModuleInit + 'static,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        // Ensure tracing has been set once
        let _ = TracingSetup::default().init();
        let real_testing = Fixtures::is_real_test();
        let (bitcoin, config, bitcoin_rpc_connection, fake_bitcoin_rpc): (
            Arc<dyn BitcoinTest>,
            BitcoinRpcConfig,
            DynServerBitcoinRpc,
            Option<DynBitcoindRpc>,
        ) = if real_testing {
            // `backend-test.sh` overrides which Bitcoin RPC to use for esplora
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

            let server_bitcoin_rpc = match rpc_config.kind.as_ref() {
                "bitcoind" => {
                    // Directly extract the authentication details from the url.
                    // Since this is just testing we can be careful to not use characters that need
                    // to be URL-encoded
                    let bitcoind_username = rpc_config.url.username();
                    let bitcoind_password = rpc_config
                        .url
                        .password()
                        .expect("bitcoind password was not set");
                    BitcoindClient::new(
                        bitcoind_username.to_string(),
                        bitcoind_password.to_string(),
                        &rpc_config.url,
                    )
                    .unwrap()
                    .into_dyn()
                }
                "esplora" => EsploraClient::new(&rpc_config.url).unwrap().into_dyn(),
                kind => panic!("Unknown bitcoin rpc kind {kind}"),
            };

            let bitcoincore_url = env::var(FM_TEST_BITCOIND_RPC_ENV)
                .expect("Must have bitcoind RPC defined for real tests")
                .parse()
                .expect("Invalid bitcoind RPC URL");
            let bitcoin = RealBitcoinTest::new(&bitcoincore_url, server_bitcoin_rpc.clone());

            (Arc::new(bitcoin), rpc_config, server_bitcoin_rpc, None)
        } else {
            let bitcoin = FakeBitcoinTest::new();

            let config = BitcoinRpcConfig {
                kind: format!("test_btc-{}", rand::random::<u64>()),
                url: "http://ignored".parse().unwrap(),
            };

            let dyn_bitcoin_rpc = IBitcoindRpc::into_dyn(bitcoin.clone());

            let server_bitcoin_rpc = IServerBitcoinRpc::into_dyn(bitcoin.clone());

            let bitcoin = Arc::new(bitcoin);

            (
                bitcoin.clone(),
                config,
                server_bitcoin_rpc,
                Some(dyn_bitcoin_rpc),
            )
        };

        Self {
            clients: ClientModuleInitRegistry::default(),
            servers: ServerModuleInitRegistry::default(),
            bitcoin_rpc: config,
            fake_bitcoin_rpc,
            bitcoin,
            server_bitcoin_rpc: bitcoin_rpc_connection,
            primary_module_kind: IClientModuleInit::module_kind(&client),
        }
        .with_module(client, server)
    }

    pub fn is_real_test() -> bool {
        env::var(FM_TEST_USE_REAL_DAEMONS_ENV) == Ok("1".to_string())
    }

    /// Add a module to the fed
    pub fn with_module(
        mut self,
        client: impl IClientModuleInit + 'static,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        self.clients.attach(DynClientModuleInit::from(client));
        self.servers.attach(DynServerModuleInit::from(server));
        self
    }

    pub fn with_server_only_module(
        mut self,
        server: impl IServerModuleInit + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        self.servers.attach(DynServerModuleInit::from(server));
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
            self.servers.clone(),
            self.clients.clone(),
            self.primary_module_kind.clone(),
            num_offline,
            self.server_bitcoin_rpc(),
        )
    }

    /// Creates a new Gateway that can be used for module tests.
    pub async fn new_gateway(&self) -> Gateway {
        // Use server_gens.iter() to match the alphabetical order used by the server
        // when assigning module instance IDs (BTreeMap iteration order)
        let module_kinds: Vec<_> = self
            .servers
            .iter()
            .enumerate()
            .map(|(id, (kind, _))| (id as ModuleInstanceId, kind.clone()))
            .collect();
        let decoders = self
            .servers
            .available_decoders(module_kinds.iter().map(|(id, kind)| (*id, kind)))
            .unwrap();
        let gateway_db = Database::new(MemDatabase::new(), decoders.clone());

        let mnemonic = Bip39RootSecretStrategy::<12>::random(&mut OsRng);
        Client::store_encodable_client_secret(&gateway_db, mnemonic.to_entropy())
            .await
            .expect("Could not generate root secret for gateway");

        let registry = self
            .clients
            .iter()
            .filter(|(kind, _)| {
                // Remove LN module because the gateway adds one
                **kind != ModuleKind::from_static_str("ln")
            })
            .filter(|(kind, _)| {
                // Remove LN NG module because the gateway adds one
                **kind != ModuleKind::from_static_str("lnv2")
            })
            .map(|(_, client)| client.clone())
            .collect();

        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: GatewayClientBuilder =
            GatewayClientBuilder::new(path.clone(), registry, DatabaseBackend::RocksDb)
                .await
                .expect("Failed to initialize gateway");

        let ln_client: Arc<dyn ILnRpcClient> = Arc::new(FakeLightningTest::new());

        let LightningInfo::Connected {
            public_key: lightning_public_key,
            alias: lightning_alias,
            network: lightning_network,
            block_height: _,
            synced_to_chain: _,
        } = ln_client.parsed_node_info().await
        else {
            panic!("Could not connect to Lightning node")
        };
        let lightning_context = LightningContext {
            lnrpc: ln_client.clone(),
            lightning_public_key,
            lightning_alias,
            lightning_network,
        };

        // Module tests do not use the webserver, so any port is ok
        let listen: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let address: SafeUrl = format!("http://{listen}").parse().unwrap();

        let esplora_server_url = SafeUrl::parse(&format!(
            "http://127.0.0.1:{}",
            env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
        ))
        .expect("Failed to parse default esplora server");
        let esplora_chain_source = ChainSource::Esplora {
            server_url: esplora_server_url,
        };

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
            esplora_chain_source,
            None,
        )
        .await
        .expect("Failed to create gateway")
    }

    /// Get a server bitcoin RPC config
    pub fn bitcoin_server(&self) -> BitcoinRpcConfig {
        self.bitcoin_rpc.clone()
    }

    pub fn client_esplora_rpc(&self) -> DynBitcoindRpc {
        let rpc = if Fixtures::is_real_test() {
            create_esplora_rpc(
                &SafeUrl::parse(&format!(
                    "http://127.0.0.1:{}/",
                    env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
                ))
                .expect("Failed to parse default esplora server"),
            )
            .unwrap()
        } else {
            self.fake_bitcoin_rpc.clone().unwrap()
        };
        BitcoindTracked::new(rpc, "test-fixture").into_dyn()
    }

    /// Get a test bitcoin fixture
    pub fn bitcoin(&self) -> Arc<dyn BitcoinTest> {
        self.bitcoin.clone()
    }

    pub fn server_bitcoin_rpc(&self) -> DynServerBitcoinRpc {
        self.server_bitcoin_rpc.clone()
    }
}
