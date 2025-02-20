use std::collections::BTreeMap;

use anyhow::{ensure, Context};
use async_trait::async_trait;
use fedimint_bitcoind::create_bitcoind;
use fedimint_core::admin_client::{ServerStatus, SetLocalParamsRequest};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::endpoint_constants::{
    ADD_PEER_CONNECTION_INFO_ENDPOINT, AUTH_ENDPOINT, CHECK_BITCOIN_STATUS_ENDPOINT,
    RESET_SETUP_ENDPOINT, SERVER_STATUS_ENDPOINT, SET_LOCAL_PARAMS_ENDPOINT, START_DKG_ENDPOINT,
};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    api_endpoint, ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio_rustls::rustls;

use crate::config::{
    gen_cert_and_key, ConfigGenParams, ConfigGenParamsConsensus, ConfigGenParamsLocal,
    ConfigGenSettings, PeerConnectionInfo,
};
use crate::net::api::{check_auth, ApiResult, HasApiContext};

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone, Default)]
pub struct ConfigGenState {
    /// Our local connection
    local_params: Option<LocalParams>,
    /// Connection info received from other guardians
    connection_info: BTreeMap<SafeUrl, PeerConnectionInfo>,
}

#[derive(Clone, Debug)]
/// Connection information sent between peers in order to start config gen
pub struct LocalParams {
    /// Our auth string
    auth: ApiAuth,
    /// Our TLS private key
    tls_private: rustls::PrivateKey,
    /// Our TLS public cert
    tls_cert: rustls::Certificate,
    /// Name of the peer, used in TLS auth
    name: String,
    /// Federation name set by the leader
    federation_name: Option<String>,
}

/// Serves the config gen API endpoints
pub struct ConfigGenApi {
    /// Our config gen settings configured locally
    settings: ConfigGenSettings,
    /// In-memory state machine
    state: Mutex<ConfigGenState>,
    /// DB not really used
    db: Database,
    /// Triggers the distributed key generation
    sender: Sender<ConfigGenParams>,
}

impl ConfigGenApi {
    pub fn new(settings: ConfigGenSettings, db: Database, sender: Sender<ConfigGenParams>) -> Self {
        Self {
            settings,
            state: Mutex::new(ConfigGenState::default()),
            db,
            sender,
        }
    }

    pub async fn server_status(&self) -> ServerStatus {
        let state = self.state.lock().await;

        match state.local_params {
            Some(..) => ServerStatus::CollectingConnectionInfo(
                state
                    .connection_info
                    .clone()
                    .into_values()
                    .map(|info| info.name)
                    .collect(),
            ),
            None => ServerStatus::AwaitingLocalParams,
        }
    }

    pub async fn reset(&self) {
        *self.state.lock().await = ConfigGenState::default();
    }

    pub async fn set_local_parameters(
        &self,
        auth: ApiAuth,
        request: SetLocalParamsRequest,
    ) -> anyhow::Result<PeerConnectionInfo> {
        ensure!(
            auth.0.trim() == auth.0,
            "Password contains leading/trailing whitespace",
        );

        let mut state = self.state.lock().await;

        if let Some(lp) = state.local_params.clone() {
            ensure!(
                lp.auth == auth,
                "Local parameters have already been set with a different auth."
            );

            ensure!(
                lp.name == request.name,
                "Local parameters have already been set with a different name."
            );

            ensure!(
                lp.federation_name == request.federation_name,
                "Local parameters have already been set with a different federation name."
            );

            let info = PeerConnectionInfo {
                cert: lp.tls_cert.clone().0,
                p2p_url: self.settings.p2p_url.clone(),
                api_url: self.settings.api_url.clone(),
                name: lp.name,
                federation_name: lp.federation_name,
            };

            return Ok(info);
        }

        let (tls_cert, tls_private) = gen_cert_and_key(&request.name)
            .expect("Failed to generate TLS for given guardian name");

        let lp = LocalParams {
            auth,
            tls_cert,
            tls_private,
            name: request.name,
            federation_name: request.federation_name,
        };

        state.local_params = Some(lp.clone());

        let info = PeerConnectionInfo {
            cert: lp.tls_cert.clone().0,
            p2p_url: self.settings.p2p_url.clone(),
            api_url: self.settings.api_url.clone(),
            name: lp.name,
            federation_name: lp.federation_name,
        };

        Ok(info)
    }

    pub async fn add_peer_connection_info(&self, info: PeerConnectionInfo) -> anyhow::Result<()> {
        ensure!(
            info.api_url != self.settings.api_url,
            "You cannot add your own connection info"
        );

        let mut state = self.state.lock().await;

        if let Some(federation_name) = state
            .connection_info
            .values()
            .find_map(|info| info.federation_name.clone())
        {
            ensure!(
                info.federation_name.is_none(),
                "Federation name has already been set to {federation_name}"
            );
        }

        state.connection_info.insert(info.api_url.clone(), info);

        Ok(())
    }

    pub async fn start_dkg(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await.clone();

        let local_params = state
            .local_params
            .clone()
            .expect("The endpoint is authenticated.");

        let our_peer_info = PeerConnectionInfo {
            cert: local_params.tls_cert.0,
            p2p_url: self.settings.p2p_url.clone(),
            api_url: self.settings.api_url.clone(),
            name: local_params.name,
            federation_name: local_params.federation_name,
        };

        state
            .connection_info
            .insert(our_peer_info.api_url.clone(), our_peer_info);

        let federation_name = state
            .connection_info
            .values()
            .find_map(|info| info.federation_name.clone())
            .context("We need one leader to configure the federation name")?;

        let our_id = state
            .connection_info
            .keys()
            .position(|url| *url == self.settings.api_url)
            .expect("We inserted the key above.");

        let params = ConfigGenParams {
            local: ConfigGenParamsLocal {
                our_id: PeerId::from(our_id as u16),
                our_private_key: local_params.tls_private,
                api_auth: local_params.auth,
                p2p_bind: self.settings.p2p_bind,
                api_bind: self.settings.api_bind,
            },
            consensus: ConfigGenParamsConsensus {
                peers: (0..)
                    .map(|i| PeerId::from(i as u16))
                    .zip(state.connection_info.values().cloned())
                    .collect(),
                meta: BTreeMap::from_iter(vec![("federation_name".to_string(), federation_name)]),
                modules: self.settings.default_params.modules.clone(),
            },
        };

        self.sender
            .send(params)
            .await
            .context("Failed to send config gen params")?;

        Ok(())
    }
}

#[async_trait]
impl HasApiContext<ConfigGenApi> for ConfigGenApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&ConfigGenApi, ApiEndpointContext<'_>) {
        assert!(id.is_none());

        let db = self.db.clone();
        let dbtx = self.db.begin_transaction().await;

        let is_authenticated = match self.state.lock().await.local_params {
            None => false,
            Some(ref params) => match request.auth.as_ref() {
                Some(auth) => *auth == params.auth,
                None => false,
            },
        };

        let context = ApiEndpointContext::new(db, dbtx, is_authenticated, request.auth.clone());

        (self, context)
    }
}

pub fn server_endpoints() -> Vec<ApiEndpoint<ConfigGenApi>> {
    vec![
        api_endpoint! {
            SERVER_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, _c, _v: ()| -> ServerStatus {
                Ok(config.server_status().await)
            }
        },
        api_endpoint! {
            SET_LOCAL_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, request: SetLocalParamsRequest| -> String {
                let auth = context
                    .request_auth()
                    .ok_or(ApiError::bad_request("Missing password".to_string()))?;

                let info = config.set_local_parameters(auth, request)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;

                Ok(info.encode_base58())
            }
        },
        api_endpoint! {
            ADD_PEER_CONNECTION_INFO_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, info: String| -> String {
                check_auth(context)?;

                let info = PeerConnectionInfo::decode_base58(&info)
                    .map_err(|e|ApiError::bad_request(e.to_string()))?;

                config.add_peer_connection_info(info.clone()).await
                    .map_err(|e|ApiError::bad_request(e.to_string()))?;

                Ok(info.name)
            }
        },
        api_endpoint! {
            START_DKG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.start_dkg().await.map_err(|e| ApiError::server_error(e.to_string()))
            }
        },
        api_endpoint! {
            RESET_SETUP_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.reset().await;

                Ok(())
            }
        },
        api_endpoint! {
            AUTH_ENDPOINT,
            ApiVersion::new(0, 0),
            async |_config: &ConfigGenApi, context, _v: ()| -> () {
                check_auth(context)?;

                Ok(())
            }
        },
        api_endpoint! {
            CHECK_BITCOIN_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |_config: &ConfigGenApi, context, _v: ()| -> BitcoinRpcConnectionStatus {
                check_auth(context)?;

                check_bitcoin_status().await
            }
        },
    ]
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct BitcoinRpcConnectionStatus {
    chain_tip_block_height: u64,
    chain_tip_block_time: u32,
    sync_percentage: Option<f64>,
}

async fn check_bitcoin_status() -> ApiResult<BitcoinRpcConnectionStatus> {
    let bitcoin_rpc_config = BitcoinRpcConfig::get_defaults_from_env_vars()
        .map_err(|e| ApiError::server_error(format!("Failed to get bitcoin rpc env vars: {e}")))?;

    let client = create_bitcoind(&bitcoin_rpc_config)
        .map_err(|e| ApiError::server_error(format!("Failed to connect to bitcoin rpc: {e}")))?;

    let block_count = client.get_block_count().await.map_err(|e| {
        ApiError::server_error(format!("Failed to get block count from bitcoin rpc: {e}"))
    })?;

    let chain_tip_block_height = block_count - 1;

    let chain_tip_block_hash = client
        .get_block_hash(chain_tip_block_height)
        .await
        .map_err(|e| {
            ApiError::server_error(format!(
                "Failed to get block hash for block count {block_count} from bitcoin rpc: {e}"
            ))
        })?;

    let chain_tip_block = client.get_block(&chain_tip_block_hash).await.map_err(|e| {
        ApiError::server_error(format!(
            "Failed to get block for block hash {chain_tip_block_hash} from bitcoin rpc: {e}"
        ))
    })?;

    let chain_tip_block_time = chain_tip_block.header.time;

    let sync_percentage = client.get_sync_percentage().await.map_err(|e| {
        ApiError::server_error(format!(
            "Failed to get sync percentage from bitcoin rpc: {e}"
        ))
    })?;

    Ok(BitcoinRpcConnectionStatus {
        chain_tip_block_height,
        chain_tip_block_time,
        sync_percentage,
    })
}
