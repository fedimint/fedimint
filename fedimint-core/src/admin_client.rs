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

    pub async fn set_password(&self, auth: ApiAuth) -> FederationResult<()> {
        self.request("/set_password", ApiRequestErased::new(auth))
            .await
    }

    pub async fn signal_upgrade(&self) -> FederationResult<()> {
        self.request("/upgrade", ApiRequestErased::default()).await
    }

    async fn request<Ret>(&self, method: &str, params: ApiRequestErased) -> FederationResult<Ret>
    where
        Ret: serde::de::DeserializeOwned + Eq + Debug + Clone + MaybeSend,
    {
        self.inner
            .request_current_consensus(method.to_owned(), params.with_auth(&self.auth))
            .await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
