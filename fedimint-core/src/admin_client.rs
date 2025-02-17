use std::collections::BTreeMap;
use std::fmt::Debug;

use anyhow::ensure;
use fedimint_core::util::SafeUrl;
use serde::{Deserialize, Serialize};
#[cfg(not(target_family = "wasm"))]
use tokio_rustls::rustls::Certificate as RustlsCertificate;

use crate::config::ServerModuleConfigGenParamsRegistry;
use crate::encoding::{Decodable, Encodable};
use crate::module::registry::ModuleDecoderRegistry;
use crate::PeerId;

/// The state of the server returned via APIs
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq, Encodable, Decodable)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatusLegacy {
    /// Server needs a password to read configs
    #[default]
    AwaitingPassword,
    /// Waiting for peers to share the config gen params
    SharingConfigGenParams,
    /// Ready to run config gen once all peers are ready
    ReadyForConfigGen,
    /// We failed running config gen
    ConfigGenFailed,
    /// Config is generated, peers should verify the config
    VerifyingConfigs,
    /// We have verified all our peer configs
    VerifiedConfigs,
    /// Consensus is running
    ConsensusRunning,
    /// Restarted setup. All peers need to sync on this state before continuing
    /// to `SharingConfigGenParams`
    SetupRestarted,
}

/// The state of the server returned via APIs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerStatus {
    AwaitingLocalParams,
    /// Waiting for peers to share the config gen params
    CollectingConnectionInfo(Vec<String>),
    /// Consensus is running
    ConsensusRunning,
}

#[cfg(target_family = "wasm")]
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Encodable, Decodable)]
struct RustlsCertificate(pub Vec<u8>);

/// Sent by admin user to the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGenConnectionsRequest {
    /// Our guardian name
    pub our_name: String,
    /// URL of "leader" guardian to send our connection info to
    /// Will be `None` if we are the leader
    pub leader_api_url: Option<SafeUrl>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Encodable)]
/// Connection information sent between peers in order to start config gen
pub struct PeerServerParams {
    /// TLS cert is necessary for P2P auth during DKG and  consensus
    #[serde(with = "serde_tls_cert")]
    pub cert: RustlsCertificate,
    /// P2P is the network for running DKG and consensus
    pub p2p_url: SafeUrl,
    /// API for secure websocket requests
    pub api_url: SafeUrl,
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Status of the peer if known
    pub status: Option<ServerStatusLegacy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetLocalParamsRequest {
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Federation name set by the leader
    pub federation_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Encodable, Decodable)]
/// Connection information sent between peers in order to start config gen
pub struct PeerConnectionInfo {
    /// TLS cert is necessary for P2P auth during DKG and consensus
    pub cert: Vec<u8>,
    /// P2P is the network for running DKG and consensus
    pub p2p_url: SafeUrl,
    /// API for secure websocket requests
    pub api_url: SafeUrl,
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Federation name set by the leader
    pub federation_name: Option<String>,
}

impl PeerConnectionInfo {
    pub fn encode_base58(&self) -> String {
        format!(
            "fedimint{}",
            bs58::encode(&self.consensus_encode_to_vec()).into_string()
        )
    }

    pub fn decode_base58(s: &str) -> anyhow::Result<Self> {
        ensure!(s.starts_with("fedimint"), "Invalid Prefix");

        let params = Self::consensus_decode_whole(
            &bs58::decode(&s[8..]).into_vec()?,
            &ModuleDecoderRegistry::default(),
        )?;

        Ok(params)
    }
}

/// The config gen params that need to be in consensus, sent by the config gen
/// leader to all the other guardians
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsConsensus {
    /// Endpoints of all servers
    pub peers: BTreeMap<PeerId, PeerConnectionInfo>,
    /// Guardian-defined key-value pairs that will be passed to the client
    pub meta: BTreeMap<String, String>,
    /// Module init params (also contains local params from us)
    pub modules: ServerModuleConfigGenParamsRegistry,
}

/// The config gen params that need to be in consensus, sent by the config gen
/// leader to all the other guardians
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsConsensusLegacy {
    /// Endpoints of all servers
    pub peers: BTreeMap<PeerId, PeerServerParams>,
    /// Guardian-defined key-value pairs that will be passed to the client
    pub meta: BTreeMap<String, String>,
    /// Module init params (also contains local params from us)
    pub modules: ServerModuleConfigGenParamsRegistry,
}

/// The config gen params response which includes our peer id
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsResponse {
    /// The same for all peers
    pub consensus: ConfigGenParamsConsensus,
    /// Our id (might change if new peers join)
    pub our_current_id: PeerId,
}

/// The config gen params response which includes our peer id
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsResponseLegacy {
    /// The same for all peers
    pub consensus: ConfigGenParamsConsensusLegacy,
    /// Our id (might change if new peers join)
    pub our_current_id: PeerId,
}

/// Config gen params that can be configured from the UI
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigGenParamsRequest {
    /// Guardian-defined key-value pairs that will be passed to the client
    pub meta: BTreeMap<String, String>,
    /// Set the params (if leader) or just the local params (if follower)
    pub modules: ServerModuleConfigGenParamsRegistry,
}

mod serde_tls_cert {
    use std::borrow::Cow;

    use hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::RustlsCertificate;

    pub fn serialize<S>(certs: &RustlsCertificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = certs.0.encode_hex::<String>();
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RustlsCertificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Cow<str> = Deserialize::deserialize(deserializer)?;
        Ok(RustlsCertificate(
            Vec::from_hex(value.as_ref()).map_err(D::Error::custom)?,
        ))
    }
}
