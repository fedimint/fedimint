use std::collections::{BTreeMap, BTreeSet};
use std::iter::once;
use std::mem::discriminant;
use std::str::FromStr as _;
use std::sync::Arc;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::admin_client::{SetLocalParamsRequest, SetupStatus};
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::Database;
use fedimint_core::endpoint_constants::{
    ADD_PEER_SETUP_CODE_ENDPOINT, RESET_PEER_SETUP_CODES_ENDPOINT, SET_LOCAL_PARAMS_ENDPOINT,
    SETUP_STATUS_ENDPOINT, START_DKG_ENDPOINT,
};
use fedimint_core::envs::{
    FM_IROH_API_SECRET_KEY_OVERRIDE_ENV, FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV,
};
use fedimint_core::module::{
    ApiAuth, ApiEndpoint, ApiEndpointContext, ApiError, ApiRequestErased, ApiVersion, api_endpoint,
};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::net::check_auth;
use fedimint_server_core::setup_ui::ISetupApi;
use iroh::SecretKey;
use rand::rngs::OsRng;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tokio_rustls::rustls;
use tracing::warn;

use super::PeerEndpoints;
use crate::config::{ConfigGenParams, ConfigGenSettings, NetworkingStack, PeerSetupCode};
use crate::net::api::HasApiContext;
use crate::net::p2p_connector::gen_cert_and_key;

/// State held by the API after receiving a `ConfigGenConnectionsRequest`
#[derive(Debug, Clone, Default)]
pub struct SetupState {
    /// Our local connection
    local_params: Option<LocalParams>,
    /// Connection info received from other guardians
    setup_codes: BTreeSet<PeerSetupCode>,
}

#[derive(Clone, Debug)]
/// Connection information sent between peers in order to start config gen
pub struct LocalParams {
    /// Our auth string
    auth: ApiAuth,
    /// Our TLS private key
    tls_key: Option<rustls::PrivateKey>,
    /// Optional secret key for our iroh api endpoint
    iroh_api_sk: Option<iroh::SecretKey>,
    /// Optional secret key for our iroh p2p endpoint
    iroh_p2p_sk: Option<iroh::SecretKey>,
    /// Our api and p2p endpoint
    endpoints: PeerEndpoints,
    /// Name of the peer, used in TLS auth
    name: String,
    /// Federation name set by the leader
    federation_name: Option<String>,
}

impl LocalParams {
    pub fn setup_code(&self) -> PeerSetupCode {
        PeerSetupCode {
            name: self.name.clone(),
            endpoints: self.endpoints.clone(),
            federation_name: self.federation_name.clone(),
        }
    }
}

/// Serves the config gen API endpoints
#[derive(Clone)]
pub struct SetupApi {
    /// Our config gen settings configured locally
    settings: ConfigGenSettings,
    /// In-memory state machine
    state: Arc<Mutex<SetupState>>,
    /// DB not really used
    db: Database,
    /// Triggers the distributed key generation
    sender: Sender<ConfigGenParams>,
}

impl SetupApi {
    pub fn new(settings: ConfigGenSettings, db: Database, sender: Sender<ConfigGenParams>) -> Self {
        Self {
            settings,
            state: Arc::new(Mutex::new(SetupState::default())),
            db,
            sender,
        }
    }

    pub async fn setup_status(&self) -> SetupStatus {
        match self.state.lock().await.local_params {
            Some(..) => SetupStatus::SharingConnectionCodes,
            None => SetupStatus::AwaitingLocalParams,
        }
    }
}

#[async_trait]
impl ISetupApi for SetupApi {
    async fn setup_code(&self) -> Option<String> {
        self.state
            .lock()
            .await
            .local_params
            .as_ref()
            .map(|lp| lp.setup_code().encode_base32())
    }

    async fn auth(&self) -> Option<ApiAuth> {
        self.state
            .lock()
            .await
            .local_params
            .as_ref()
            .map(|lp| lp.auth.clone())
    }

    async fn connected_peers(&self) -> Vec<String> {
        self.state
            .lock()
            .await
            .setup_codes
            .clone()
            .into_iter()
            .map(|info| info.name)
            .collect()
    }

    async fn reset_setup_codes(&self) {
        self.state.lock().await.setup_codes.clear();
    }

    async fn set_local_parameters(
        &self,
        auth: ApiAuth,
        name: String,
        federation_name: Option<String>,
    ) -> anyhow::Result<String> {
        ensure!(!name.is_empty(), "The guardian name is empty");

        ensure!(!auth.0.is_empty(), "The password is empty");

        ensure!(
            auth.0.trim() == auth.0,
            "The password contains leading/trailing whitespace",
        );

        if let Some(federation_name) = federation_name.as_ref() {
            ensure!(!federation_name.is_empty(), "The federation name is empty");
        }

        let mut state = self.state.lock().await;

        ensure!(
            state.local_params.is_none(),
            "Local parameters have already been set"
        );

        let lp = match self.settings.networking {
            NetworkingStack::Tcp => {
                let (tls_cert, tls_key) = gen_cert_and_key(&name)
                    .expect("Failed to generate TLS for given guardian name");

                LocalParams {
                    auth,
                    tls_key: Some(tls_key),
                    iroh_api_sk: None,
                    iroh_p2p_sk: None,
                    endpoints: PeerEndpoints::Tcp {
                        api_url: self
                            .settings
                            .api_url
                            .clone()
                            .ok_or_else(|| anyhow::format_err!("Api URL must be configured"))?,
                        p2p_url: self
                            .settings
                            .p2p_url
                            .clone()
                            .ok_or_else(|| anyhow::format_err!("P2P URL must be configured"))?,

                        cert: tls_cert.0,
                    },
                    name,
                    federation_name,
                }
            }
            NetworkingStack::Iroh => {
                warn!(target: LOG_SERVER, "Iroh support is experimental");
                let iroh_api_sk = if let Ok(var) =
                    std::env::var(FM_IROH_API_SECRET_KEY_OVERRIDE_ENV)
                {
                    SecretKey::from_str(&var)
                        .with_context(|| format!("Parsing {FM_IROH_API_SECRET_KEY_OVERRIDE_ENV}"))?
                } else {
                    SecretKey::generate(&mut OsRng)
                };

                let iroh_p2p_sk = if let Ok(var) =
                    std::env::var(FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV)
                {
                    SecretKey::from_str(&var)
                        .with_context(|| format!("Parsing {FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV}"))?
                } else {
                    SecretKey::generate(&mut OsRng)
                };

                LocalParams {
                    auth,
                    tls_key: None,
                    iroh_api_sk: Some(iroh_api_sk.clone()),
                    iroh_p2p_sk: Some(iroh_p2p_sk.clone()),
                    endpoints: PeerEndpoints::Iroh {
                        api_pk: iroh_api_sk.public(),
                        p2p_pk: iroh_p2p_sk.public(),
                    },
                    name,
                    federation_name,
                }
            }
        };

        state.local_params = Some(lp.clone());

        Ok(lp.setup_code().encode_base32())
    }

    async fn add_peer_setup_code(&self, info: String) -> anyhow::Result<String> {
        let info = PeerSetupCode::decode_base32(&info)?;

        let mut state = self.state.lock().await;

        if state.setup_codes.contains(&info) {
            return Ok(info.name.clone());
        }

        let local_params = state
            .local_params
            .clone()
            .expect("The endpoint is authenticated.");

        ensure!(
            info != local_params.setup_code(),
            "You cannot add you own connection info"
        );

        ensure!(
            discriminant(&info.endpoints) == discriminant(&local_params.endpoints),
            "Guardian has different endpoint variant (TCP/Iroh) than us.",
        );

        if let Some(federation_name) = state
            .setup_codes
            .iter()
            .chain(once(&local_params.setup_code()))
            .find_map(|info| info.federation_name.clone())
        {
            ensure!(
                info.federation_name.is_none(),
                "Federation name has already been set to {federation_name}"
            );
        }

        state.setup_codes.insert(info.clone());

        Ok(info.name)
    }

    async fn start_dkg(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await.clone();

        let local_params = state
            .local_params
            .clone()
            .expect("The endpoint is authenticated.");

        let our_setup_code = local_params.setup_code();

        state.setup_codes.insert(our_setup_code.clone());

        ensure!(
            state.setup_codes.len() == 1 || state.setup_codes.len() >= 4,
            "The number of guardians is invalid"
        );

        let federation_name = state
            .setup_codes
            .iter()
            .find_map(|info| info.federation_name.clone())
            .context("We need one guardian to configure the federations name")?;

        let our_id = state
            .setup_codes
            .iter()
            .position(|info| info == &our_setup_code)
            .expect("We inserted the key above.");

        let params = ConfigGenParams {
            identity: PeerId::from(our_id as u16),
            tls_key: local_params.tls_key,
            iroh_api_sk: local_params.iroh_api_sk,
            iroh_p2p_sk: local_params.iroh_p2p_sk,
            api_auth: local_params.auth,
            peers: (0..)
                .map(|i| PeerId::from(i as u16))
                .zip(state.setup_codes.clone().into_iter())
                .collect(),
            meta: BTreeMap::from_iter(vec![(
                META_FEDERATION_NAME_KEY.to_string(),
                federation_name,
            )]),
        };

        self.sender
            .send(params)
            .await
            .context("Failed to send config gen params")?;

        Ok(())
    }
}

#[async_trait]
impl HasApiContext<SetupApi> for SetupApi {
    async fn context(
        &self,
        request: &ApiRequestErased,
        id: Option<ModuleInstanceId>,
    ) -> (&SetupApi, ApiEndpointContext<'_>) {
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

pub fn server_endpoints() -> Vec<ApiEndpoint<SetupApi>> {
    vec![
        api_endpoint! {
            SETUP_STATUS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, _c, _v: ()| -> SetupStatus {
                Ok(config.setup_status().await)
            }
        },
        api_endpoint! {
            SET_LOCAL_PARAMS_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, request: SetLocalParamsRequest| -> String {
                let auth = context
                    .request_auth()
                    .ok_or(ApiError::bad_request("Missing password".to_string()))?;

                 config.set_local_parameters(auth, request.name, request.federation_name)
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))
            }
        },
        api_endpoint! {
            ADD_PEER_SETUP_CODE_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, info: String| -> String {
                check_auth(context)?;

                config.add_peer_setup_code(info.clone())
                    .await
                    .map_err(|e|ApiError::bad_request(e.to_string()))
            }
        },
        api_endpoint! {
            RESET_PEER_SETUP_CODES_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.reset_setup_codes().await;

                Ok(())
            }
        },
        api_endpoint! {
            START_DKG_ENDPOINT,
            ApiVersion::new(0, 0),
            async |config: &SetupApi, context, _v: ()| -> () {
                check_auth(context)?;

                config.start_dkg().await.map_err(|e| ApiError::server_error(e.to_string()))
            }
        },
    ]
}
