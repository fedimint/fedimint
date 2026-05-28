use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::bail;
use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::core::ModuleKind;
use crate::encoding::{Decodable, Encodable};
use crate::util::SafeUrl;

/// On-chain wallet descriptor used by the walletv2 module.
///
/// Selected by the federation leader at setup time and broadcast to peers
/// via `PeerSetupCode`. Defaults to [`Self::Wsh`] when the leader doesn't
/// configure it.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub enum WalletDescriptorKind {
    /// SegWit v0 (P2WSH) with ECDSA k-of-n multisig.
    #[default]
    Wsh,
    /// Taproot (P2TR) with Schnorr k-of-n multisig.
    Tr,
    /// Taproot (P2TR) with FROST threshold signing.
    Frost,
}

impl FromStr for WalletDescriptorKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "wsh" => Ok(Self::Wsh),
            "tr" => Ok(Self::Tr),
            "frost" => Ok(Self::Frost),
            other => {
                bail!("Unknown wallet descriptor kind '{other}'; expected one of: wsh, tr, frost")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable, Serialize)]
/// Connection information sent between peers in order to start config gen
pub struct PeerSetupCode {
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// The peer's api and p2p endpoint
    pub endpoints: PeerEndpoints,
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
    /// Bitcoin network configured locally by the guardian
    pub network: Network,
    /// On-chain wallet descriptor for the walletv2 module. Set by the
    /// leader from the `FM_WALLETV2_DESCRIPTOR` env var. `None` on
    /// follower peers; the leader's value wins via the reconciliation in
    /// `set_local_parameters`.
    pub descriptor_kind: Option<WalletDescriptorKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable, Serialize)]
pub enum PeerEndpoints {
    Tcp {
        /// Url for our websocket api endpoint
        api_url: SafeUrl,
        /// Url for our websocket p2p endpoint
        p2p_url: SafeUrl,
        /// TLS certificate for our websocket p2p endpoint#
        #[serde(with = "::fedimint_core::encoding::as_hex")]
        cert: Vec<u8>,
    },
    Iroh {
        /// Public key for our iroh api endpoint
        api_pk: iroh_base::PublicKey,
        /// Public key for our iroh p2p endpoint
        p2p_pk: iroh_base::PublicKey,
    },
}
