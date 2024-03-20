use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::util::SafeUrl;
pub use fedimintd::*;

mod fedimintd;

pub mod envs;

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    let url = match network {
        Network::Bitcoin => SafeUrl::parse("https://blockstream.info/api/")
            .expect("Failed to parse default esplora server"),
        Network::Testnet => SafeUrl::parse("https://blockstream.info/testnet/api/")
            .expect("Failed to parse default esplora server"),
        Network::Regtest => SafeUrl::parse(&format!(
            "http://127.0.0.1:{}/",
            std::env::var("FM_PORT_ESPLORA").unwrap_or(String::from("50002"))
        ))
        .expect("Failed to parse default esplora server"),
        Network::Signet => SafeUrl::parse("https://mutinynet.com/api/")
            .expect("Failed to parse default esplora server"),
    };
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url,
    }
}
