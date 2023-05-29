use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen, IClientModuleGen};
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::{
    ModuleGenParams, ServerModuleGenParamsRegistry, ServerModuleGenRegistry,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::{DynServerModuleGen, IServerModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync};
use ln_gateway::lnrpc_client::ILnRpcClient;
use tempfile::TempDir;

use crate::btc::mock::FakeBitcoinFactory;
use crate::btc::BitcoinTest;
use crate::federation::FederationTest;
use crate::gateway::GatewayTest;
use crate::ln::mock::FakeLightningTest;
use crate::ln::LightningTest;

/// A default timeout for things happening in tests
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// Offset from the normal port by 30000 to avoid collisions
static BASE_PORT: AtomicU16 = AtomicU16::new(38173);

/// A tool for easily writing fedimint integration tests
pub struct Fixtures {
    num_peers: u16,
    ids: Vec<ModuleInstanceId>,
    clients: Vec<DynClientModuleGen>,
    servers: Vec<DynServerModuleGen>,
    params: ServerModuleGenParamsRegistry,
    primary_client: ModuleInstanceId,
    bitcoin_rpc: BitcoinRpcConfig,
    bitcoin: Arc<dyn BitcoinTest>,
    lightning: Arc<dyn LightningTest>,
    lightning_client: Arc<dyn ILnRpcClient>,
}

impl Fixtures {
    pub fn new_primary(
        id: ModuleInstanceId,
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        let real_testing = env::var("FM_TEST_USE_REAL_DAEMONS") == Ok("1".to_string());
        let num_peers = match real_testing {
            true => 2,
            false => 1,
        };
        let FakeBitcoinFactory { bitcoin, config } = FakeBitcoinFactory::register_new();

        let lightning = Arc::new(FakeLightningTest::new());
        Self {
            num_peers,
            ids: vec![],
            clients: vec![],
            servers: vec![],
            params: Default::default(),
            primary_client: id,
            bitcoin_rpc: config,
            bitcoin: Arc::new(bitcoin),
            lightning: lightning.clone(),
            lightning_client: lightning,
        }
        .with_module(id, client, server, params)
    }

    // TODO: Auto-assign instance ids after removing legacy id order
    /// Add a module to the fed
    pub fn with_module(
        mut self,
        id: ModuleInstanceId,
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        self.params
            .attach_config_gen_params(id, server.module_kind(), params);
        self.ids.push(id);
        self.clients.push(DynClientModuleGen::from(client));
        self.servers.push(DynServerModuleGen::from(server));

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

    /// Starts a new gateway
    pub async fn new_gateway(&self, password: Option<String>) -> GatewayTest {
        // TODO: Make construction easier
        let server_gens = ServerModuleGenRegistry::from(self.servers.clone());
        let module_kinds = self.params.iter_modules().map(|(id, kind, _)| (id, kind));
        let decoders = server_gens.decoders(module_kinds).unwrap();

        let password = password.unwrap_or_else(|| rand::random::<u64>().to_string());

        GatewayTest::new(
            BASE_PORT.fetch_add(1, Ordering::Relaxed),
            password,
            FakeLightningTest::new(),
            decoders,
            ClientModuleGenRegistry::from(self.clients.clone()),
        )
        .await
    }

    /// Starts a new gateway connected to a fed
    pub async fn new_connected_gateway(&self, fed: &FederationTest) -> GatewayTest {
        let mut gateway = self.new_gateway(None).await;

        gateway.connect_fed(fed).await;
        gateway
    }

    /// Get a test bitcoin RPC config
    pub fn bitcoin_rpc(&self) -> BitcoinRpcConfig {
        self.bitcoin_rpc.clone()
    }

    /// Get a test bitcoin fixture
    pub fn bitcoin(&self) -> Arc<dyn BitcoinTest> {
        self.bitcoin.clone()
    }

    /// Get a test lightning fixture
    pub fn lightning(&self) -> (Arc<dyn LightningTest>, Arc<dyn ILnRpcClient>) {
        (self.lightning.clone(), self.lightning_client.clone())
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
