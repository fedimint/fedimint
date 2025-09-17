use serde::Serialize;

use crate::encoding::{Decodable, Encodable};
use crate::util::SafeUrl;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encodable, Decodable, Serialize)]
/// Connection information sent between peers in order to start config gen
pub struct PeerSetupCode {
    /// Name of the peer, used in TLS auth
    pub name: String,
    /// The peer's api and p2p endpoint
    pub endpoints: PeerEndpoints,
    /// Federation name set by the leader
    pub federation_name: Option<String>,
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
