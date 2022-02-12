use tide;
use mint_client::{MintClient};
use std::{path::PathBuf, sync::Arc};
use minimint::config::{load_from_file, ClientConfig};
use serde::Serialize;
use structopt::StructOpt;
use tide::Body;
use minimint_api::{Amount, TransactionId};
use mint_client::mint::SpendableCoin;
use minimint::modules::mint::tiered::coins::Coins;
use bitcoin_hashes::hex::ToHex;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;


#[derive(Clone)]
pub struct State {
    mint_client: Arc<MintClient>,
}

#[derive(StructOpt)]
struct Opts {
    workdir: PathBuf,
}

#[derive(Serialize)]
struct InfoResponse {
    total : CoinTotal,
    coins : Vec<CoinGrouped>,
}
#[derive(Serialize)]
struct CoinTotal{
    coin_count : usize,
    amount : Amount,
}
#[derive(Serialize)]
struct CoinGrouped{
    amount : usize,
    tier : u64
}
#[derive(Serialize)]
struct SpendResponse {
    token : String,
}

#[derive(Serialize)]
struct ReissueResponse {
    id : String,
    fetched : Vec<TransactionId>,
}


impl InfoResponse {
    fn new(coins: Coins<SpendableCoin>) -> Self {
        let info_total =  CoinTotal { coin_count: coins.coin_count(), amount: coins.amount() };
        let info_coins : Vec<CoinGrouped> = coins.coins.iter()
            .map(|(tier, c)| CoinGrouped { amount : c.len(), tier : tier.milli_sat})
            .collect();
        InfoResponse { total : info_total, coins : info_coins }
    }
}

impl ReissueResponse {
    async fn new(mint_client :&MintClient, coins:Coins<SpendableCoin>) -> Self {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let id = mint_client.reissue(coins, &mut rng).await.unwrap();

        let  id = id.to_hex();
        let  fetched : Vec<TransactionId>= mint_client.fetch_all_coins().await.unwrap();
        let res = ReissueResponse {
            id,
            fetched,
        };
        res
    }
}
#[tokio::main]
async fn main() -> tide::Result<()>{
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    info!("no waring");
    error!("no warning");
    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap() //handle error ?
        .open_tree("mint-client")
        .unwrap(); //handle error ?
    let client = MintClient::new(cfg, Arc::new(db), Default::default());


    let state = State {
        mint_client: Arc::new(client),
    };
    let mut app = tide::with_state(state);

    //need move because async block could outlive the post function and needs to take ownership of req ?
    app.at("/info").post(|req : tide::Request<State>| async move{
        let State {
            ref mint_client,
        } = req.state();
        Body::from_json(&InfoResponse::new(mint_client.coins()))
    });


      app.at("/spend").post(|mut req : tide::Request<State>| async move {
          let value : u64 = req.body_json().await.expect("expected diffrent json");
     let State {
            ref mint_client,
        } = req.state();
          let amount = Amount::from_sat(value);
          let mut token = String::from("error");
              match mint_client.select_and_spend_coins(amount) {
                  Ok(outgoing_coins) => {
                      token = serialize_coins(&outgoing_coins)
                  }
                  Err(_e) => {
                      //TODO return error in body
                  }
              };
          Body::from_json(&SpendResponse{token})
    });

    app.at("/reissue").post(|mut req : tide::Request<State>| async move {
        let value : String = req.body_json().await?;
        let State {
            ref mint_client,
        } = req.state();

        let coins : Coins<SpendableCoin> = parse_coins(&value);
        Body::from_json(&ReissueResponse::new(&mint_client, coins).await)

    });

    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

