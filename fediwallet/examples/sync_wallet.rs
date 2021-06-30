use bitcoin::Network;
use config::{Feerate, WalletConfig};
use fediwallet::Wallet;
use secp256k1::SecretKey;
use std::str::FromStr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = WalletConfig {
        network: Network::Regtest,
        peg_in_descriptor:
            "pkh(020ce4ee685363eac4ed72c323d1a3ebc994a0df9705f182bb2a2ee54a70a5ae8d)"
                .parse()
                .unwrap(),
        peg_in_key: SecretKey::from_str(
            "020ce4ee685363eac4ed72c323d1a3ebc994a0df9705f182bb2a2ee54a70a5ae",
        )
        .expect("parse fake key failed"),
        finalty_delay: 100,
        default_fee: Feerate { sats_per_kvb: 2000 },
        start_consensus_height: 501,
        per_utxo_fee: Default::default(),
        btc_rpc_address: "127.0.0.1".to_string(),
        btc_rpc_user: "bitcoin".to_string(),
        btc_rpc_pass: "bitcoin".to_string(), // use your own credentials for testing
    };

    let sled_db = sled::open("cfg/wallet_test")
        .unwrap()
        .open_tree("mint")
        .unwrap();

    let (wallet, _, _) = Wallet::new(cfg, sled_db).await.unwrap();

    println!("Synced up to block {}", wallet.consensus_height());
}
