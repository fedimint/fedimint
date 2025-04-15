#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::large_futures)]

/// Module for creating `fedimintd` binary with custom modules
use bitcoin::Network;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::SafeUrl;
pub use fedimintd::*;

mod fedimintd;

pub mod envs;
use crate::envs::FM_PORT_ESPLORA_ENV;

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url: match network {
            Network::Bitcoin => SafeUrl::parse("https://mempool.space/api/"),
            Network::Testnet => SafeUrl::parse("https://mempool.space/testnet/api/"),
            Network::Testnet4 => SafeUrl::parse("https://mempool.space/testnet4/api/"),
            Network::Signet => SafeUrl::parse("https://mutinynet.com/api/"),
            Network::Regtest => SafeUrl::parse(&format!(
                "http://127.0.0.1:{}/",
                std::env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
            )),
            _ => panic!("Failed to parse default esplora server"),
        }
        .expect("Failed to parse default esplora server"),
    }
}
