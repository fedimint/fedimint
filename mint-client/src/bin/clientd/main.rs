use tide;
use tide::Request;
use tide::Response;
use mint_client::{MintClient, ResBody,parse_coins, serialize_coins};
use std::{path::PathBuf, sync::Arc};
use minimint::config::{load_from_file, ClientConfig};
use structopt::StructOpt;
use tide::Body;
use minimint_api::{Amount};
use mint_client::mint::{SpendableCoin};
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

#[tokio::main]
async fn main() -> tide::Result<()>{
    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap() //handle error ?
        .open_tree("mint-client")
        .unwrap();
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
    let body= Body::from_json(&ResBody::build_info(mint_client.coins(), cfd))?; // *1 Do I want to build a ResBody::Err instead ?
    Ok(body.into())
}

/// Endpoint:Pending responds with all pending coins
async fn pending(req : Request<State>) -> tide::Result {
    let mint_client = &req.state().mint_client;
    let cfd = mint_client.fetch_active_issuances();
    let body= Body::from_json(&ResBody::build_pending(cfd))?; // 1*
    Ok(body.into())
}
/// Endpoint:Spend responds with (adequately) selected spendable coins
async fn spend(mut req: Request<State>) -> tide::Result {
    let value : u64 = match req.body_json().await {
        Ok(i) => i,
        Err(e) => { //Approach A
            let res = ResBody::Error {err : format!("{:?}", e)}; //this dosent seem right
            let body = Body::from_json(&res)?; // 1*
            return Ok(body.into());
        },
    };
    let mint_client = &req.state().mint_client;
    let amount = Amount::from_sat(value);
    let res = match mint_client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => {
            ResBody::build_spend(serialize_coins(&outgoing_coins))
        }
        Err(e) => {
            ResBody::Error {err : format!("{:?}", e)} //this dosent seem right
        }
    };
    let body = Body::from_json(&res)?; // 1*
    Ok(body.into())
}
///Endpoint:ReissueValidate starts reissuance and responds when accepted (blocking)
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let value : String = req.body_json().await?; //Approach B
    let mint_client = &req.state().mint_client;

    let coins : Coins<SpendableCoin> = parse_coins(&value);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = mint_client.reissue(coins, &mut rng).await?;
    let status = match mint_client.fetch_tx_outcome(out_point.txid, true).await{
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s
    };
    let body = Body::from_json(&ResBody::build_reissue(out_point, status))?;
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
        let out_point = match mint_client_task.reissue(coins, &mut rng).await {
            Ok(o) => o,
            Err(_) => return, //Send via channel to a logger ?
        };
        match mint_client_task.fetch_tx_outcome(out_point.txid, true).await{
            Ok(_) => fetch(mint_client_task).await,
            Err(_) => (), //Send via channel to a logger ?
        };
    });
    //Use ResBody::Empty ?
    Ok(Response::new(200))
}

async fn fetch(mint_client : Arc<MintClient>) {
    //log the returned txids ?
    match mint_client.fetch_all_coins().await {
        Ok(_) => (), //Send via channel to a logger ?
        Err(_) => () //Send via channel to a logger ?
    }
}