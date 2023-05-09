use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::{env, fs};

use fedimint_client::module::gen::{ClientModuleGenRegistry, DynClientModuleGen, IClientModuleGen};
use fedimint_core::config::{
    ModuleGenParams, ServerModuleGenParamsRegistry, ServerModuleGenRegistry,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::{DynServerModuleGen, IServerModuleGen};
use fedimint_core::task::{MaybeSend, MaybeSync};
use tempfile::TempDir;

use crate::federation::FederationTest;
use crate::gateway::GatewayTest;
use crate::ln::mock::FakeLightningTest;

// Offset from the normal port by 30000 to avoid collisions
static BASE_PORT: AtomicU16 = AtomicU16::new(38173);

/// A tool for easily writing fedimint integration tests
#[derive(Default)]
pub struct Fixtures {
    ids: Vec<ModuleInstanceId>,
    clients: Vec<DynClientModuleGen>,
    servers: Vec<DynServerModuleGen>,
    params: ServerModuleGenParamsRegistry,
    primary_client: ModuleInstanceId,
}

impl Fixtures {
    /// Add primary client module to the fed
    // TODO: Auto-assign instance ids after removing legacy id order
    pub fn with_primary(
        mut self,
        id: ModuleInstanceId,
        client: impl IClientModuleGen + MaybeSend + MaybeSync + 'static,
        server: impl IServerModuleGen + MaybeSend + MaybeSync + 'static,
        params: impl ModuleGenParams,
    ) -> Self {
        self.primary_client = id;
        self.with_module(id, client, server, params)
    }

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

    /// Starts a new federation
    pub async fn new_fed(&self, num_peers: u16) -> FederationTest {
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
    pub async fn new_gateway(&self) -> GatewayTest {
        // TODO: Make construction easier
        let server_gens = ServerModuleGenRegistry::from(self.servers.clone());
        let module_kinds = self.params.iter_modules().map(|(id, kind, _)| (id, kind));
        let decoders = server_gens.decoders(module_kinds).unwrap();

        GatewayTest::new(
            BASE_PORT.fetch_add(1, Ordering::Relaxed),
            FakeLightningTest::new(),
            decoders,
            ClientModuleGenRegistry::from(self.clients.clone()),
        )
        .await
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
