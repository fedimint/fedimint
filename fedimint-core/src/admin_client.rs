use std::fmt::Debug;

use fedimint_core::task::MaybeSend;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use url::Url;

use crate::api::{DynFederationApi, FederationApiExt, FederationResult, WsFederationApi};
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
        self.request_auth("/set_password", ApiRequestErased::new(auth))
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
        self.request_auth("/set_config_gen_connections", ApiRequestErased::new(info))
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
        self.request("/add_config_gen_peer", ApiRequestErased::new(peer))
            .await
    }

    /// During config gen, gets all the server connections we've received from
    /// peers using `add_config_gen_peer`
    ///
    /// Could be called on the leader, so it's not authenticated
    pub async fn get_config_gen_peers(&self) -> FederationResult<Vec<PeerServerParams>> {
        self.request("/get_config_gen_peers", ApiRequestErased::default())
            .await
    }

    /// During config gen, waits to receive server connections from a number of
    /// `peers`
    pub async fn await_config_gen_peers(
        &self,
        peers: usize,
    ) -> FederationResult<Vec<PeerServerParams>> {
        self.request("/await_config_gen_peers", ApiRequestErased::new(peers))
            .await
    }

    /// Sends a signal to consensus that we are ready to shutdown the federation
    /// and upgrade
    pub async fn signal_upgrade(&self) -> FederationResult<()> {
        self.request_auth("/upgrade", ApiRequestErased::default())
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
pub struct PeerServerParams {
    #[serde(with = "serde_tls_cert")]
    pub cert: rustls::Certificate,
    pub p2p_url: Url,
    pub api_url: Url,
    pub name: String,
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
