use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use bitcoin_hashes::sha256;
use fedimint_core::task::MaybeSend;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use url::{Url, ParseError};

use crate::api::{DynFederationApi, FederationApiExt, FederationResult, WsFederationApi};
use crate::config::ServerModuleGenParamsRegistry;
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
    pub async fn set_password(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request_auth("set_password", ApiRequestErased::new(auth))
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

    /// During config gen, waits to receive server connections from a number of
    /// `peers`
    pub async fn await_config_gen_peers(
        &self,
        peers: usize,
    ) -> FederationResult<Vec<PeerServerParams>> {
        self.request("await_config_gen_peers", ApiRequestErased::new(peers))
            .await
    }

    /// Sends a signal to consensus that we are ready to shutdown the federation
    /// and upgrade
    pub async fn signal_upgrade(&self) -> FederationResult<()> {
        self.request_auth("upgrade", ApiRequestErased::default())
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
    ) -> FederationResult<ConfigGenParamsConsensus> {
        self.request(
            "get_consensus_config_gen_params",
            ApiRequestErased::default(),
        )
        .await
    }

    /// Runs DKG, can only be called once after configs have been generated in
    /// `get_consensus_config_gen_params`.  If DKG fails this returns a 500
    /// error and config gen must be restarted.
    pub async fn run_dkg(&self) -> FederationResult<ConfigGenParamsConsensus> {
        self.request_auth("run_dkg", ApiRequestErased::default())
            .await
    }

    /// After DKG, returns the hash of the consensus config tweaked with our id.
    /// We need to share this with all other peers to complete verification.
    pub async fn get_verify_config_hash(&self) -> FederationResult<sha256::Hash> {
        self.request_auth("get_verify_config_hash", ApiRequestErased::default())
            .await
    }

    /// After we exchange verification hashes with other peers, we call this to
    /// confirm we all have the same consensus configs.
    pub async fn verify_configs(
        &self,
        user_hashes: BTreeSet<sha256::Hash>,
    ) -> FederationResult<()> {
        self.request_auth("verify_configs", ApiRequestErased::new(user_hashes))
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

impl ConfigGenConnectionsRequest {
    pub fn new(our_name: String, leader_api_url_string: Option<String>) -> Result<Self, ParseError> {
        let leader_api_url = match leader_api_url_string {
            Some(url_string) => {
                let replaced_url_string = url_string.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
                Some(Url::from_str(&replaced_url_string)?)
            },
            None => None,
        };
        Ok(Self {
            our_name,
            leader_api_url,
        })
    }
}





#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerServerParams {
    #[serde(with = "serde_tls_cert")]
    pub cert: rustls::Certificate,
    pub p2p_url: Url,
    pub api_url: Url,
    pub name: String,
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
