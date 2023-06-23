use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use fedimint_bitcoind::create_bitcoind;
use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen, IClientModuleGen};
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::{
    ModuleGenParams, ServerModuleGenParamsRegistry, ServerModuleGenRegistry,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::module::{DynServerModuleGen, IServerModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync, TaskGroup};
use fedimint_logging::TracingSetup;
use tempfile::TempDir;

use crate::btc::mock::FakeBitcoinFactory;
use crate::btc::real::RealBitcoinTest;
use crate::btc::BitcoinTest;
use crate::federation::FederationTest;
use crate::gateway::GatewayTest;
use crate::ln::mock::FakeLightningTest;
use crate::ln::real::{ClnLightningTest, LndLightningTest};
use crate::ln::LightningTest;

/// A default timeout for things happening in tests
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Offset from the normal port by 30000 to avoid collisions
static BASE_PORT: AtomicU16 = AtomicU16::new(38173);

/// A tool for easily writing fedimint integration tests
pub struct Fixtures {
    num_peers: u16,
    clients: Vec<DynClientModuleGen>,
    servers: Vec<DynServerModuleGen>,
    params: ServerModuleGenParamsRegistry,
    primary_client: ModuleInstanceId,
    bitcoin_rpc: BitcoinRpcConfig,
    bitcoin: Arc<dyn BitcoinTest>,
    id: ModuleInstanceId,
}

impl Fixtures {
    pub fn new_primary(
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        // Ensure tracing has been set once
        let _ = TracingSetup::default().init();
        let real_testing = Fixtures::is_real_test();
        let num_peers = match real_testing {
            true => 2,
            false => 1,
        };
        let task_group = TaskGroup::new();
        let (bitcoin, config): (Arc<dyn BitcoinTest>, BitcoinRpcConfig) = match real_testing {
            true => {
                let rpc_config = BitcoinRpcConfig::from_env_vars().unwrap();
                let bitcoin_rpc = create_bitcoind(&rpc_config, task_group.make_handle()).unwrap();
                let bitcoincore_url = env::var("FM_TEST_BITCOIND_RPC")
                    .expect("Must have bitcoind RPC defined for real tests")
                    .parse()
                    .expect("Invalid bitcoind RPC URL");
                let bitcoin = RealBitcoinTest::new(&bitcoincore_url, bitcoin_rpc);
                (Arc::new(bitcoin), rpc_config)
            }
            false => {
                let FakeBitcoinFactory { bitcoin, config } = FakeBitcoinFactory::register_new();
                (Arc::new(bitcoin), config)
            }
        };

        Self {
            num_peers,
            clients: vec![],
            servers: vec![],
            params: Default::default(),
            primary_client: 0,
            bitcoin_rpc: config,
            bitcoin,
            id: 0,
        }
        .with_module(client, server, params)
    }

    pub fn is_real_test() -> bool {
        env::var("FM_TEST_USE_REAL_DAEMONS") == Ok("1".to_string())
    }

    // TODO: Auto-assign instance ids after removing legacy id order
    /// Add a module to the fed
    pub fn with_module(
        mut self,
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        self.params
            .attach_config_gen_params(self.id, server.module_kind(), params);
        self.clients.push(DynClientModuleGen::from(client));
        self.servers.push(DynServerModuleGen::from(server));
        self.id += 1;

        self
    }

    /// Starts a new federation with default number of peers for testing
    pub async fn new_fed(&self) -> FederationTest {
        self.new_fed_with_peers(self.num_peers).await
    }

    /// Starts a new federation with number of peers
    pub async fn new_fed_with_peers(&self, num_peers: u16) -> FederationTest {
        FederationTest::new(
            num_peers,
            BASE_PORT.fetch_add(num_peers * 2, Ordering::Relaxed),
            self.params.clone(),
            ServerModuleGenRegistry::from(self.servers.clone()),
            ClientModuleGenRegistry::from(self.clients.clone()),
            self.primary_client,
        )
        .await
    }

    /// Starts a new gateway with a given lightning node
    pub async fn new_gateway(&self, ln: Arc<dyn LightningTest>) -> GatewayTest {
        // TODO: Make construction easier
        let server_gens = ServerModuleGenRegistry::from(self.servers.clone());
        let module_kinds = self.params.iter_modules().map(|(id, kind, _)| (id, kind));
        let decoders = server_gens.decoders(module_kinds).unwrap();
        let clients = self.clients.clone().into_iter();

        GatewayTest::new(
            BASE_PORT.fetch_add(1, Ordering::Relaxed),
            rand::random::<u64>().to_string(),
            ln,
            decoders,
            ClientModuleGenRegistry::from_iter(clients.filter(|client| {
                // Remove LN module because the gateway adds one
                client.to_dyn_common().module_kind() != ModuleKind::from_static_str("ln")
            })),
        )
        .await
    }

    /// Returns the LND lightning node
    pub async fn lnd(&self) -> Arc<dyn LightningTest> {
        match Fixtures::is_real_test() {
            true => Arc::new(LndLightningTest::new().await),
            false => Arc::new(FakeLightningTest::new()),
        }
    }

    /// Returns the CLN lightning node
    pub async fn cln(&self) -> Arc<dyn LightningTest> {
        match Fixtures::is_real_test() {
            true => {
                let dir = env::var("FM_TEST_DIR").expect("Real tests require FM_TEST_DIR");
                Arc::new(ClnLightningTest::new(&dir).await)
            }
            false => Arc::new(FakeLightningTest::new()),
        }
    }

    /// Get a server bitcoin RPC config
    pub fn bitcoin_server(&self) -> BitcoinRpcConfig {
        self.bitcoin_rpc.clone()
    }

    /// Get a client bitcoin RPC config
    // TODO: Right now we only support mocks or esplora, we should support others in
    // the future
    pub fn bitcoin_client(&self) -> BitcoinRpcConfig {
        match Fixtures::is_real_test() {
            true => BitcoinRpcConfig {
                kind: "esplora".to_string(),
                url: "http://127.0.0.1:50002".parse().unwrap(),
            },
            false => self.bitcoin_rpc.clone(),
        }
    }

    /// Get a test bitcoin fixture
    pub fn bitcoin(&self) -> Arc<dyn BitcoinTest> {
        self.bitcoin.clone()
    }
}

/// If `FM_TEST_DIR` is set, use it as a base, otherwise use a tempdir
///
/// Callers must hold onto the tempdir until it is no longer needed
pub fn test_dir(pathname: &str) -> (PathBuf, Option<TempDir>) {
    let (parent, maybe_tmp_dir_guard) = match env::var("FM_TEST_DIR") {
        Ok(directory) => (directory, None),
        Err(_) => {
            let random = format!("test-{}", rand::random::<u64>());
            let guard = tempfile::Builder::new().prefix(&random).tempdir().unwrap();
            let directory = guard.path().to_str().unwrap().to_owned();
            (directory, Some(guard))
        }
    };
    let fullpath = PathBuf::from(parent).join(pathname);
    fs::create_dir_all(fullpath.clone()).expect("Can make dirs");
    (fullpath, maybe_tmp_dir_guard)
}
