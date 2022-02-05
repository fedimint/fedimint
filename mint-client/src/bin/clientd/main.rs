use tide;
use mint_client::{MintClient};
use std::{path::PathBuf, sync::Arc};
use minimint::config::{load_from_file, ClientConfig};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use tide::Body;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use minimint_api::Amount;
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

#[derive(Debug, Deserialize, Serialize)]
struct InfoResponse {
    total : serde_json::Value,
    coins : serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReissueResponse {
    id : serde_json::Value,
    fetched : serde_json::Value
}

#[derive(Deserialize,Serialize, Debug)]
struct ReqBody<T> {
    //I dont like this
    value : T
}

impl InfoResponse {
    fn new(coins: Coins<SpendableCoin>) -> Self{
        //just ignore this ugly block of code pls (will refactor)
        let mut total_map =serde_json::map::Map::new();
        let mut coins_map =serde_json::map::Map::new();
        let mut coins_arr : Vec<serde_json::Value> = vec![serde_json::Value::Null];
        total_map.insert("coins".to_owned(), serde_json::json!(coins.coin_count()));
        total_map.insert("amount".to_owned(), serde_json::json!(coins.amount()));
        for (amount, coins) in coins.coins {
            info!("We own {} coins of denomination {}", coins.len(), amount);
            coins_map.insert("denomination".to_owned(), serde_json::json!(amount));
            coins_map.insert("amount".to_owned(), serde_json::json!(coins.len()));
            coins_arr.push(serde_json::json!(coins_map));
        }
        let  json_total = serde_json::Value::Object(total_map);
        let  json_coins = serde_json::Value::Array(coins_arr);
        let res = InfoResponse {
            total : json_total,
            coins : json_coins
        };
        res
    }
}

impl ReissueResponse {
    async fn new(client :&MintClient, coins:Coins<SpendableCoin>) -> Self {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let mut coins_map = serde_json::Map::new();
        let mut fetched_arr : Vec<serde_json::Value> = vec![serde_json::Value::Null];
        info!("Starting reissuance transaction for {}", coins.amount());
        let id = client.reissue(coins, &mut rng).await.unwrap();
        info!(
                "Started reissuance {}, result will be fetched",
                id.to_hex()
            );
        coins_map.insert("coins".to_owned(), serde_json::json!(  id.to_hex()));
        //make mime application/octet-stream chunked so client dosent have to wait in idle(endpoint caller dosent get blocked)
        for id in client.fetch_all_coins().await.unwrap() {
            info!("Fetched coins from issuance {}", id.to_hex());
            fetched_arr.push(serde_json::json!(id.to_hex()));
        }
        let  json_coins = serde_json::Value::Object(coins_map);
        let  json_fetched = serde_json::Value::Array(fetched_arr);
        let res = ReissueResponse {
            id: json_coins,
            fetched: json_fetched
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
        let res = InfoResponse::new(mint_client.coins());
        Body::from_json(&res)
    });


      app.at("/spend").post(|mut req : tide::Request<State>| async move {
          let req_body : ReqBody<u64> = req.body_json().await?;
     let State {
            ref mint_client,
        } = req.state();

          let mut res : serde_json::Value = serde_json::Value::Null;
          let amount = Amount::from_sat(req_body.value);

          match mint_client.select_and_spend_coins(amount) {
              Ok(outgoing_coins) => {
                  println!("{}", serialize_coins(&outgoing_coins));
                  res = json!(&serialize_coins(&outgoing_coins));
              }
              Err(e) => {
                  error!("Error: {:?}", e);
                  //TODO return error in body
              }
          };
          Body::from_json(&res)
    });

    app.at("/reissue").post(|mut req : tide::Request<State>| async move {
        let req_body : ReqBody<String> = req.body_json().await?;
        let State {
            ref mint_client,
        } = req.state();


        let coins : Coins<SpendableCoin> = parse_coins(&req_body.value);

        let res = ReissueResponse::new(&mint_client, coins).await; //should not block caller -> respond chunked
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

