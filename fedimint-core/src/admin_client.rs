use std::fmt::Debug;

use fedimint_core::util::SafeUrl;
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, Encodable};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Connection information sent between peers in order to start config gen
pub struct PeerServerParamsLegacy {
    /// TLS cert is necessary for P2P auth during DKG and  consensus
    pub cert: String,
    /// P2P is the network for running DKG and consensus
    pub p2p_url: SafeUrl,
    /// API for secure websocket requests
    pub api_url: SafeUrl,
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Status of the peer if known
    pub status: Option<ServerStatusLegacy>,
}

/// The state of the server returned via APIs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegacySetupStatus {
    /// Waiting for guardian to set the local parameters
    AwaitingLocalParams,
    /// Sharing the connection codes with our peers
    SharingConnectionCodes,
    /// Consensus is running
    ConsensusIsRunning,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetLocalParamsRequest {
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// Federation name set by the leader
    pub federation_name: Option<String>,
}
