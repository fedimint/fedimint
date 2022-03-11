use tide;
use tide::Request;
use tide::Response;
use mint_client::{MintClient};
use std::{path::PathBuf, sync::Arc};
use minimint::config::{load_from_file, ClientConfig};
use serde::Serialize;
use structopt::StructOpt;
use tide::Body;
use minimint_api::{Amount, OutPoint};
use mint_client::mint::{CoinFinalizationData, SpendableCoin};
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;


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
    pending : PendingResponse,
}

#[derive(Serialize)]
struct PendingResponse {
    transactions : usize,
    acc_coins : usize,
    acc_amount : Amount,
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
    out_point : OutPoint,
    status : TransactionStatus,
}

impl PendingResponse {
    fn new(all_pending : Vec<CoinFinalizationData>) -> Self {
        let acc_coins = all_pending.iter().map(|cfd| cfd.coin_count()).sum();
        let acc_amount = all_pending.iter().map(|cfd| cfd.coin_amount()).sum();
        PendingResponse { transactions : all_pending.len(), acc_coins, acc_amount }
    }
}
impl InfoResponse {
    fn new(coins: Coins<SpendableCoin>, cfd : Vec<CoinFinalizationData>) -> Self {
        let info_total =  CoinTotal { coin_count: coins.coin_count(), amount: coins.amount() };
        let info_coins : Vec<CoinGrouped> = coins.coins.iter()
            .map(|(tier, c)| CoinGrouped { amount : c.len(), tier : tier.milli_sat})
            .collect();
        InfoResponse { total : info_total, coins : info_coins, pending : PendingResponse::new(cfd)}
    }
}

impl ReissueResponse {
     fn new(out_point : OutPoint, status : TransactionStatus) -> ReissueResponse {

        ReissueResponse {
            out_point,
            status,
        }
    }
}
#[tokio::main]
async fn main() -> tide::Result<()>{
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

    app.at("/info").post(info);
    app.at("/spend").post(spend);
    app.at("/reissue").post(reissue);
    app.at("/reissue_validate").post(reissue_validate);
    app.at("/pending").post(pending);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}

/// Endpoint:Info responds with total coins owned, coins owned for every tier, and pending (not signed but accepted) coins
async fn info(req: Request<State>) -> tide::Result {
    let mint_client = &req.state().mint_client;
    let cfd = mint_client.fetch_active_issuances();
    let body= Body::from_json(&InfoResponse::new(mint_client.coins(), cfd)).expect("encoding error");
    Ok(body.into())
}

/// Endpoint:Pending responds with all pending coins
async fn pending(req : Request<State>) -> tide::Result {
    let mint_client = &req.state().mint_client;
    let cfd = mint_client.fetch_active_issuances();
    let body= Body::from_json(&PendingResponse::new(cfd)).expect("encoding error");
    Ok(body.into())
}
/// Endpoint:Spend responds with (adequately) selected spendable coins
async fn spend(mut req: Request<State>) -> tide::Result {
    let value : u64 = req.body_json().await.expect("expected diffrent json");
    let mint_client = &req.state().mint_client;
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
    let body = Body::from_json(&SpendResponse{token}).unwrap();
    Ok(body.into())
}
///Endpoint:ReissueValidate starts reissuance and responds when accepted (blocking)
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let value : String = req.body_json().await?;
    let mint_client = &req.state().mint_client;

    let coins : Coins<SpendableCoin> = parse_coins(&value);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = mint_client.reissue(coins, &mut rng).await.unwrap();
    let status = match mint_client.fetch_tx_outcome(out_point.txid, true).await{
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s
    };
    let body = Body::from_json(&ReissueResponse::new(out_point, status)).unwrap();
    let c = Arc::clone(&mint_client);
    tokio::spawn(async move {
        fetch(c).await;
    });
    Ok(body.into())
}
///Endpoint:Reissue starts reissuance, the caller has to be aware that this might fail
async fn reissue(mut req: Request<State>) -> tide::Result {
    let value : String = req.body_json().await?;
    let mint_client = &req.state().mint_client;
    let mint_client_task = Arc::clone(&mint_client);
    tokio::spawn(async move {
        let coins : Coins<SpendableCoin> = parse_coins(&value);
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let out_point = mint_client_task.reissue(coins, &mut rng).await.unwrap();
        match mint_client_task.fetch_tx_outcome(out_point.txid, true).await{
            Err(_) => (), //maybe save somehow
            Ok(s) => fetch(mint_client_task).await,
        };
    });
    Ok(Response::new(200))
}

async fn fetch(mint_client : Arc<MintClient>) {
    //log the returned txids ?
    mint_client.fetch_all_coins().await;
}

fn serialize_coins(c: &Coins<SpendableCoin>) -> String {
    let bytes = bincode::serialize(&c).unwrap();
    base64::encode(&bytes)
}

fn parse_coins(s: &str) -> Coins<SpendableCoin> {
    let bytes = base64::decode(s).unwrap();
    bincode::deserialize(&bytes).unwrap()
}

