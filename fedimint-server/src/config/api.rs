use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::module::{
    api_endpoint, ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased,
};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;

use crate::net::api::{attach_endpoints, HasApiContext, RpcHandlerCtx};

/// Serves the config API endpoints
pub struct ConfigApi {
    /// Directory the configs will be created in
    _data_dir: PathBuf,
    /// In-memory state machine
    state: Mutex<ConfigApiState>,
    /// DB not really used
    db: Database,
    /// Bind address for the API
    _bind_api: SocketAddr,
}

impl ConfigApi {
    pub fn new(data_dir: PathBuf, bind_api: SocketAddr, db: Database) -> Self {
        Self {
            _data_dir: data_dir,
            state: Mutex::new(ConfigApiState::SetPassword),
            db,
            _bind_api: bind_api,
        }
    }

    // Sets the auth and decryption key derived from the password
    pub fn set_password(&self, auth: ApiAuth) -> Result<(), ApiError> {
        let mut state = self.state.lock().expect("lock poisoned");

        if *state != ConfigApiState::SetPassword {
            Err(ApiError::bad_request("Password already set".to_string()))
        } else {
            *state = ConfigApiState::SetPeerConnectionInfo(auth);
            Ok(())
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// State machine for config generation, required in a top-to-bottom order
pub enum ConfigApiState {
    /// Guardian must first enter a password for auth/decryption
    SetPassword,
    /// Guardian must add connection info for at least 1 peer
    SetPeerConnectionInfo(ApiAuth),
    /// A guardian (possibly us) must set the config gen parameters
    SetConfigParams,
    /// Guardian must verify the correct config gen params
    VerifyConfigParams,
    /// Running DKG may take a minute
    RunningDkg,
    /// Configs are created, awaiting guardian verification
    VerifyConsensusConfig,
    /// We all agree on consensus configs, we can run consensus
    RunningConsensus,
}

#[async_trait]
impl HasApiContext<ConfigApi> for ConfigApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConfigApi, ApiEndpointContext<'_>) {
        let dbtx = self.db.begin_transaction().await;
        let state = self.state.lock().expect("locks");
        let has_auth = match &*state {
            ConfigApiState::SetPeerConnectionInfo(info) => Some(info.clone()) == request.auth,
            // The first client to connect gets the set the password
            _ => true,
        };

        (self, ApiEndpointContext::new(has_auth, dbtx, id))
    }
}

/// Starts the configuration server
// TODO: combine with net::run_server and replace DKG CLI with the API
pub async fn run_server(data_dir: PathBuf, bind_api: SocketAddr, db: Database) -> ServerHandle {
    let state = RpcHandlerCtx {
        rpc_context: Arc::new(ConfigApi::new(data_dir, bind_api, db)),
    };
    let mut rpc_module = RpcModule::new(state);

    attach_endpoints(&mut rpc_module, config_endpoints(), None);

    ServerBuilder::new()
        .max_connections(10)
        .ping_interval(Duration::from_secs(10))
        .build(&bind_api.to_string())
        .await
        .expect("Could not start API server")
        .start(rpc_module)
        .expect("Could not start API server")
}

/// Returns the endpoints that are necessary prior to the config being generated
fn config_endpoints() -> Vec<ApiEndpoint<ConfigApi>> {
    vec![api_endpoint! {
        "/set_password",
        async |config: &ConfigApi, _context, auth: ApiAuth| -> () {
            config.set_password(auth)
        }
    }]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::{env, fs};

    use fedimint_core::admin_client::WsAdminClient;
    use fedimint_core::api::FederationResult;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::Database;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::module::ApiAuth;
    use fedimint_core::PeerId;
    use jsonrpsee::server::ServerHandle;

    use crate::config::api::run_server;

    /// Helper in config API tests for simulating a guardian's client and server
    struct TestConfigApi {
        client: WsAdminClient,
        server: ServerHandle,
        auth: ApiAuth,
    }

    impl TestConfigApi {
        async fn set_password(&self) -> FederationResult<()> {
            self.client.set_password(self.auth.clone()).await
        }
    }

    async fn server_client(port: u16, data_dir: PathBuf) -> TestConfigApi {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

        let socket = format!("127.0.0.1:{port}").parse().expect("parses");
        let url = format!("ws://127.0.0.1:{port}").parse().expect("parses");
        let server = run_server(data_dir.clone(), socket, db).await;
        // our id doesn't really exist at this point
        let auth = ApiAuth(format!("password-{port}"));
        let client = WsAdminClient::new(url, PeerId::from(0), auth.clone());
        TestConfigApi {
            client,
            server,
            auth,
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_config_api() {
        let (parent, _maybe_tmp_dir_guard) = match env::var("FM_TEST_DIR") {
            Ok(directory) => (directory, None),
            Err(_) => {
                let guard = tempfile::Builder::new()
                    .prefix("fm-cfg-api")
                    .tempdir()
                    .unwrap();
                let directory = guard.path().to_str().unwrap().to_owned();
                (directory, Some(guard))
            }
        };

        let data_dir = PathBuf::from(parent).join("test-config-api");
        fs::create_dir(data_dir.clone()).expect("Unable to create test dir");

        // TODO: Choose port in common way with `fedimint_env`
        let api1 = server_client(18103, data_dir.clone()).await;

        api1.set_password().await.unwrap();
        // Cannot set the password twice
        assert!(api1.set_password().await.is_err());

        api1.server.stop().expect("stops");
        fs::remove_dir(data_dir).expect("Unable to remove dir");
    }
}
