use bitcoin_hashes::hex::ToHex;
use config::{load_from_file, ClientConfig};
use mint_api::{Amount, Coins};
use mint_client::{MintClient, SpendableCoin};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(StructOpt)]
struct Options {
    workdir: PathBuf,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    PegIn {
        amount: Amount,
    },
    Reissue {
        #[structopt(parse(from_str = parse_coins))]
        coins: Coins<SpendableCoin>,
    },
    Spend {
        amount: Amount,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts: Options = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let mut rng = rand::rngs::OsRng::new().unwrap();

    let client = MintClient::new(cfg, db);

    match opts.command {
        Command::PegIn { amount } => {
            info!("Starting peg-in transaction for {}", amount);
            let id = client.peg_in(amount, &mut rng).await.unwrap();
            info!(
                "Started peg-in {}, please fetch the result later",
                id.to_hex()
            );
        }
        Command::Reissue { .. } => {
            unimplemented!()
        }
        Command::Spend { .. } => {
            unimplemented!()
        }
    }
}

fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}
