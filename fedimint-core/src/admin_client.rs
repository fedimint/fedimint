use std::collections::BTreeSet;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::ModuleKind;
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

/// The state of the server returned via APIs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetupStatus {
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
    /// Whether to disable base fees, set by the leader
    pub disable_base_fees: Option<bool>,
    /// Modules enabled by the leader (if None, all available modules are
    /// enabled)
    pub enabled_modules: Option<BTreeSet<ModuleKind>>,
    /// Total number of guardians (including the one who sets this), set by the
    /// leader
    pub federation_size: Option<u32>,
}

/// Archive of all the guardian config files that can be used to recover a lost
/// guardian node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianConfigBackup {
    #[serde(with = "crate::hex::serde")]
    pub tar_archive_bytes: Vec<u8>,
}
