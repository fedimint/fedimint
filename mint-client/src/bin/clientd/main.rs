use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint_api::Amount;
use mint_client::clients::user::{PendingRes, ResBody};
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tide::{Body, Request, Response};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    client: Arc<UserClient>,
}

#[derive(StructOpt)]
struct Options {
    workdir: PathBuf,
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let opts: Options = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: ClientAndGatewayConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let client = UserClient::new(cfg.client, Box::new(db), Default::default());
    let state = State {
        client: Arc::new(client),
    };
    let mut app = tide::with_state(state);

    app.at("/info").post(info);
    app.at("/spend").post(spend);
    app.at("/reissue").post(reissue);
    app.at("/reissue_validate").post(reissue_validate);
    app.at("/pending").post(pending);
    app.at("/events").post(events);
    app.listen("127.0.0.1:8080").await?;
    Ok(())
}
/// Endpoint: responds with [`ResBody::Info`]
async fn info(req: Request<State>) -> tide::Result {
    let client = &req.state().client;
    let cfd = client.fetch_active_issuances();
    //This will never fail since ResBody is always build with reliable constructors and cant be 'messed up' so unwrap is ok
    let body = Body::from_json(&ResBody::build_info(client.coins(), cfd)).unwrap();
    Ok(body.into())
}
/// Endpoint: responds with [`ResBody::Spend`], when reissue-ing use everything in the raw json after "token"
async fn spend(mut req: Request<State>) -> tide::Result {
    let value: u64 = match req.body_json().await {
        Ok(i) => i,
        Err(_) => panic!("error reading body"),
    };
    let client = &req.state().client;
    let amount = Amount::from_sat(value);
    let res = match client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => ResBody::build_spend(outgoing_coins),
        Err(_) => panic!("error in spend"),
    };
    //Unwrap ok
    let body = Body::from_json(&res).unwrap();
    Ok(body.into())
}
/// Endpoint: always responds with Status 200. The caller has to be aware that it can fail and might query /event afterwards.
async fn reissue(mut req: Request<State>) -> tide::Result {
    let coins: Coins<SpendableCoin> = req.body_json().await?;
    let client = Arc::clone(&req.state().client);
    tokio::spawn(async move {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let out_point = match client.reissue(coins, &mut rng).await {
            Ok(o) => o,
            Err(_) => panic!("error in reissue"),
        };
        match client.fetch_tx_outcome(out_point.txid, true).await {
            Ok(_) => fetch(client).await,
            Err(_) => panic!("error in reissue while fetching outcome"),
        };
    });
    Ok(Response::new(200))
}
/// Endpoint: starts a re-issuance and responds with [`ResBody::Reissue`], and fetches in the background
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let coins: Coins<SpendableCoin> = req.body_json().await?; //Approach B
    let client = Arc::clone(&req.state().client);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = client.reissue(coins, &mut rng).await?;
    let status = match client.fetch_tx_outcome(out_point.txid, true).await {
        Err(_) => panic!("error while fetching outcome"),
        Ok(s) => s,
    };
    let body = Body::from_json(&ResBody::build_reissue(out_point, status))?;
    tokio::spawn(async move {
        fetch(client).await;
    });
    Ok(body.into())
}
/// Endpoint: responds with [`PendingRes`]
async fn pending(req: Request<State>) -> tide::Result {
    let client = &req.state().client;
    let cfd = client.fetch_active_issuances();
    //This will never fail since ResBody is always build with reliable constructors and cant be 'messed up' so unwrap is ok
    let body = Body::from_json(&PendingRes::build_pending(cfd)).unwrap();
    Ok(body.into())
}
async fn events(_req: Request<State>) -> tide::Result {
    let mut res = Response::new(200);
    res.set_body(String::from("events"));
    Ok(res)
}

async fn fetch(client: Arc<UserClient>) {
    match client.fetch_all_coins().await {
        Ok(_) => info!("succsessfull fetch"),
        Err(_) => info!("error in fetch"),
    }
}
