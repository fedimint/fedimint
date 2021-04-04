use bitcoin::Network;
use bitcoincore_rpc_async::{Auth, Client};
use fediwallet::{Feerate, Wallet, WalletConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let rpc = Client::new(
        "http://10.0.0.1:8332".into(),
        Auth::UserPass("bitcoin".into(), "bitcoin".into()), // use your own credentials for testing
    )
    .await
    .unwrap();

    let cfg = WalletConfig {
        network: Network::Bitcoin,
        descriptor: "pkh(xpub661MyMwAqRbcFoma4tsGNgSDDsTQJtNKzWmemTN9DxppP31zdh7YRWeX7JzgfXarphQdPDLYrC3QzBcWpg6tz77tebXKYiFHYu6AVWhHXzj)".parse().unwrap(),
        signing_key: "xprv9s21ZrQH143K3Kh6xsLG1YVUfqcuuReUdHr3y4xXfdHqWEgr69oHsiL3G4NBJqvbwHKYaV876SHNBvDEs6vtBu4ouDh6NS4K4pTPiTbajtR".parse().unwrap(),
        finalty_delay: 100,
        default_fee: Feerate {
            sats_per_kb: 2000
        },
        start_consensus_height: 501,
    };

    let sled_db = sled::open("cfg/wallet_test")
        .unwrap()
        .open_tree("mint")
        .unwrap();

    let wallet = Wallet::new(cfg, rpc, sled_db).await.unwrap();

    println!("Synced up to block {}", wallet.consensus_height());
}
