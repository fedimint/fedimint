use std::collections::BTreeMap;
use std::fmt::Debug;

use bitcoin_hashes::sha256;
use fedimint_core::task::MaybeSend;
use serde::{Deserialize, Serialize};
use threshold_crypto::PublicKey;
use tokio_rustls::rustls;
use url::Url;

use crate::api::{
    DynFederationApi, FederationApiExt, FederationResult, GlobalFederationApi, ServerStatus,
    StatusResponse, WsFederationApi,
};
use crate::config::ServerModuleGenParamsRegistry;
use crate::epoch::{SerdeEpochHistory, SignedEpochOutcome};
use crate::module::registry::ModuleDecoderRegistry;
use crate::module::{ApiAuth, ApiRequestErased};
use crate::PeerId;

/// For a guardian to communicate with their server
// TODO: Maybe should have it's own CLI client so it doesn't need to be in core
pub struct WsAdminClient {
    inner: DynFederationApi,
    auth: ApiAuth,
}

impl WsAdminClient {
    pub fn new(url: Url, our_id: PeerId, auth: ApiAuth) -> Self {
        Self {
            inner: WsFederationApi::new(vec![(our_id, url)]).into(),
            auth,
        }
    }

    /// Sets the password used to decrypt the configs and authenticate
    ///
    /// Must be called first before any other calls to the API
    pub async fn set_password(&self) -> FederationResult<()> {
        self.request_auth("set_password", ApiRequestErased::default())
            .await
    }

    /// During config gen, sets the server connection containing our endpoints
    ///
    /// Optionally sends our server info to the config gen leader using
    /// `add_config_gen_peer`
    pub async fn set_config_gen_connections(
        &self,
        info: ConfigGenConnectionsRequest,
    ) -> FederationResult<()> {
        self.request_auth("set_config_gen_connections", ApiRequestErased::new(info))
            .await
    }

    /// During config gen, used for an API-to-API call that adds a peer's server
    /// connection info to the leader.
    ///
    /// Note this call will fail until the leader has their API running and has
    /// `set_server_connections` so clients should retry.
    ///
    /// This call is not authenticated because it's guardian-to-guardian
    pub async fn add_config_gen_peer(&self, peer: PeerServerParams) -> FederationResult<()> {
        self.request("add_config_gen_peer", ApiRequestErased::new(peer))
            .await
    }

    /// During config gen, gets all the server connections we've received from
    /// peers using `add_config_gen_peer`
    ///
    /// Could be called on the leader, so it's not authenticated
    pub async fn get_config_gen_peers(&self) -> FederationResult<Vec<PeerServerParams>> {
        self.request("get_config_gen_peers", ApiRequestErased::default())
            .await
    }

    /// Sends a signal to consensus that we are ready to shutdown the federation
    /// and upgrade
    pub async fn signal_upgrade(&self) -> FederationResult<()> {
        self.request_auth("upgrade", ApiRequestErased::default())
            .await
    }

    /// Sends a signal to consensus that we want to force running an epoch
    /// outcome
    pub async fn force_process_epoch(&self, outcome: SerdeEpochHistory) -> FederationResult<()> {
        self.request_auth("process_outcome", ApiRequestErased::new(outcome))
            .await
    }

    /// Delegates to `fetch_epoch_history`
    pub async fn fetch_last_epoch_history(
        &self,
        epoch_pk: PublicKey,
        decoders: &ModuleDecoderRegistry,
    ) -> FederationResult<SignedEpochOutcome> {
        let epoch = self.inner.fetch_epoch_count().await? - 1;
        self.inner
            .fetch_epoch_history(epoch, epoch_pk, decoders)
            .await
    }

    /// Gets the default config gen params which can be configured by the
    /// leader, gives them a template to modify
    pub async fn get_default_config_gen_params(&self) -> FederationResult<ConfigGenParamsRequest> {
        self.request_auth("get_default_config_gen_params", ApiRequestErased::default())
            .await
    }

    /// Used by the leader to set the config gen params, after which
    /// `ConfigGenParams` can be created
    pub async fn set_config_gen_params(
        &self,
        requested: ConfigGenParamsRequest,
    ) -> FederationResult<()> {
        self.request_auth("set_config_gen_params", ApiRequestErased::new(requested))
            .await
    }

    /// Returns the consensus config gen params, followers will delegate this
    /// call to the leader.  Once this endpoint returns successfully we can run
    /// DKG.
    pub async fn get_consensus_config_gen_params(
        &self,
    ) -> FederationResult<ConfigGenParamsResponse> {
        self.request(
            "get_consensus_config_gen_params",
            ApiRequestErased::default(),
        )
        .await
    }

    /// Runs DKG, can only be called once after configs have been generated in
    /// `get_consensus_config_gen_params`.  If DKG fails this returns a 500
    /// error and config gen must be restarted.
    pub async fn run_dkg(&self) -> FederationResult<()> {
        self.request_auth("run_dkg", ApiRequestErased::default())
            .await
    }

    /// After DKG, returns the hash of the consensus config tweaked with our id.
    /// We need to share this with all other peers to complete verification.
    pub async fn get_verify_config_hash(&self) -> FederationResult<BTreeMap<PeerId, sha256::Hash>> {
        self.request_auth("get_verify_config_hash", ApiRequestErased::default())
            .await
    }

    /// Reads the configs from the disk, starts the consensus server, and shuts
    /// down the config gen API to start the Fedimint API
    ///
    /// Clients may receive an error due to forced shutdown, should call the
    /// `server_status` to see if consensus has started.
    pub async fn start_consensus(&self) -> FederationResult<()> {
        self.request_auth("start_consensus", ApiRequestErased::default())
            .await
    }

    /// Returns the status of the server
    pub async fn status(&self) -> FederationResult<StatusResponse> {
        self.request_auth("status", ApiRequestErased::default())
            .await
    }

    async fn request_auth<Ret>(
        &self,
        method: &str,
        params: ApiRequestErased,
    ) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.inner
            .request_current_consensus(method.to_owned(), params.with_auth(&self.auth))
            .await
    }

    async fn request<Ret>(&self, method: &str, params: ApiRequestErased) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.inner
            .request_current_consensus(method.to_owned(), params)
            .await
    }
}

/// Sent by admin user to the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGenConnectionsRequest {
    /// Our guardian name
    pub our_name: String,
    /// Url of "leader" guardian to send our connection info to
    /// Will be `None` if we are the leader
    pub leader_api_url: Option<Url>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
/// Connection information sent between peers in order to start config gen
pub struct PeerServerParams {
    /// TLS cert is necessary for P2P auth during DKG and  consensus
    #[serde(with = "serde_tls_cert")]
    pub cert: rustls::Certificate,
    /// P2P is the network for running DKG and consensus
    pub p2p_url: Url,
    /// API for secure websocket requests
    pub api_url: Url,
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Status of the peer if known
    pub status: Option<ServerStatus>,
}

/// The config gen params that need to be in consensus, sent by the config gen
/// leader to all the other guardians
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsConsensus {
    /// Endpoints of all servers
    pub peers: BTreeMap<PeerId, PeerServerParams>,
    /// Params that were configured by the leader
    pub requested: ConfigGenParamsRequest,
}

/// The config gen params response which includes our peer id
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsResponse {
    /// The same for all peers
    pub consensus: ConfigGenParamsConsensus,
    /// Our id (might change if new peers join)
    pub our_current_id: PeerId,
}

/// Config gen values that can be configured by the config gen leader
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsRequest {
    /// Guardian-defined key-value pairs that will be passed to the client.
    /// These should be the same for all guardians since they become part of
    /// the consensus config.
    pub meta: BTreeMap<String, String>,
    /// Params for the modules we wish to configure, can contain custom
    /// parameters
    pub modules: ServerModuleGenParamsRegistry,
}

mod serde_tls_cert {
    use std::borrow::Cow;

    use bitcoin_hashes::hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use tokio_rustls::rustls;

    pub fn serialize<S>(certs: &rustls::Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = certs.0.to_hex();
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Cow<str> = Deserialize::deserialize(deserializer)?;
        Ok(rustls::Certificate(
            Vec::from_hex(&value).map_err(D::Error::custom)?,
        ))
    }
}
