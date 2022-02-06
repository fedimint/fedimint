use tide;
use mint_client::{MintClient};
use std::{path::PathBuf, sync::Arc};
use minimint::config::{load_from_file, ClientConfig};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tide::Body;
use tracing::{error};
use tracing_subscriber::EnvFilter;
use minimint_api::{Amount, TransactionId};
use mint_client::mint::SpendableCoin;
use minimint::modules::mint::tiered::coins::Coins;
use serde_json::json;
use bitcoin_hashes::hex::ToHex;



#[derive(Clone)]
pub struct State {
    mint_client: Arc<MintClient>,
}

#[derive(StructOpt)]
struct Opts {
    workdir: PathBuf,
}

/*
#[derive(Debug, Deserialize, Serialize)]
struct InfoResponse {
    total : serde_json::Value,
    coins : serde_json::Value,
}
*/
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

#[derive(Deserialize,Serialize, Debug)]
struct ReqBody<T> {
    //I dont like this
    value : T
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
    //collect trace to print info
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();


    //Instantiate Client
    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap() //handle error ?
        .open_tree("mint-client")
        .unwrap(); //handle error ?
    let client = MintClient::new(cfg, Arc::new(db), Default::default()); //Why Arc ?


    let state = State {
        mint_client: Arc::new(client),
    };
    let mut app = tide::with_state(state);

    //need move because async block could outlive the post function and needs to take ownership of req ?
    app.at("/info").post(|req : tide::Request<State>| async move{
        let State {
            ref mint_client,
        } = req.state();
        let res = json!(InfoResponse::new(mint_client.coins()));
        Body::from_json(&res)
    });


      app.at("/spend").post(|mut req : tide::Request<State>| async move {
          let req_body : ReqBody<u64> = req.body_json().await?;
     let State {
            ref mint_client,
        } = req.state();
          let amount = Amount::from_sat(req_body.value);
          let mut token = String::from("error");
              match mint_client.select_and_spend_coins(amount) {
                  Ok(outgoing_coins) => {
                      token = serialize_coins(&outgoing_coins)
                  }
                  Err(e) => {
                      error!("Error: {:?}", e);
                      //TODO return error in body
                  }
              };
          let res = json!(SpendResponse{token});
          Body::from_json(&res)
    });

    app.at("/reissue").post(|mut req : tide::Request<State>| async move {
        //make mime application/octet-stream chunked
        let req_body : ReqBody<String> = req.body_json().await?;
        let State {
            ref mint_client,
        } = req.state();
        
        let coins : Coins<SpendableCoin> = parse_coins(&req_body.value);
        let res = json!(ReissueResponse::new(&mint_client, coins).await);
        Body::from_json(&res)

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

