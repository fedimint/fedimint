use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;
use minimint_api::Amount;
use mint_client::clients::user::{PendingRes, ResBody};
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use std::borrow::BorrowMut;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use tide::{Body, Request, Response};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    client: Arc<UserClient>,
    events: Arc<Mutex<Vec<ResBody>>>,
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
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let mut app = tide::with_state(state);

    app.at("/info").post(info);
    app.at("/pegin_address").post(pegin_address);
    app.at("/spend").post(spend);
    app.at("/reissue").post(reissue);
    app.at("/reissue_validate").post(reissue_validate);
    app.at("/pending").post(pending);
    app.at("/events").post(events);
    app.listen("127.0.0.1:8081").await?;
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
/// Endpoint: responds with a [`bitcoin::util::address`], which can be used to peg-in funds to receive e-cash
async fn pegin_address(req: Request<State>) -> tide::Result {
    let client = Arc::clone(&req.state().client);
    let mut rng = rand::rngs::OsRng::new()?; //probably just put that in state later
    let address = client.get_new_pegin_address(&mut rng);
    // I think it's unnecessary to build a new ResBody variant but I don't know maybe it's bad practice because of inconsistency ?
    //unwrap always ok
    let body = Body::from_json(&ResBody::PegInAddress {
        pegin_address: address,
    })
    .unwrap();
    Ok(body.into())
}
/// Endpoint: responds with [`ResBody::Spend`], when reissue-ing use everything in the raw json after "token"
async fn spend(mut req: Request<State>) -> tide::Result {
    let value: u64 = match req.body_json().await {
        Ok(i) => i,
        Err(e) => {
            let res = ResBody::build_event(format!("{:?}", e));
            //Will be always Ok so unwrap is ok
            let body = Body::from_json(&res).unwrap();
            return Ok(body.into());
        }
    };
    let client = &req.state().client;
    let amount = Amount::from_sat(value);
    let res = match client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => ResBody::build_spend(outgoing_coins),
        Err(e) => ResBody::build_event(format!("{:?}", e)),
    };
    //Unwrap ok
    let body = Body::from_json(&res).unwrap();
    Ok(body.into())
}
/// Endpoint: always responds with Status 200. The caller has to be aware that it can fail and might query /event afterwards.
async fn reissue(mut req: Request<State>) -> tide::Result {
    let coins: Coins<SpendableCoin> = req.body_json().await?;
    let client = Arc::clone(&req.state().client);
    let events = Arc::clone(&req.state().events);
    tokio::spawn(async move {
        let mut rng = rand::rngs::OsRng::new().unwrap();
        let out_point = match client.reissue(coins, &mut rng).await {
            Ok(o) => o,
            Err(e) => {
                events
                    .lock()
                    .unwrap()
                    .push(ResBody::build_event(format!("{:?}", e)));
                return;
            }
        };
        match client.fetch_tx_outcome(out_point.txid, true).await {
            Ok(_) => fetch(client, Arc::clone(&events)).await,
            Err(e) => (*events.lock().unwrap()).push(ResBody::build_event(format!("{:?}", e))),
        };
    });
    Ok(Response::new(200))
}
/// Endpoint: starts a re-issuance and responds with [`ResBody::Reissue`], and fetches in the background
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let coins: Coins<SpendableCoin> = req.body_json().await?;
    let client = Arc::clone(&req.state().client);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = client.reissue(coins, &mut rng).await?;
    let status = match client.fetch_tx_outcome(out_point.txid, true).await {
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s,
    };
    let body = Body::from_json(&ResBody::build_reissue(out_point, status))?;
    let events = Arc::clone(&req.state().events);
    tokio::spawn(async move {
        fetch(client, events).await;
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
/// Endpoint: responds with [`ResBody::EventDump`]
async fn events(req: Request<State>) -> tide::Result {
    let events_ptr = Arc::clone(&req.state().events);
    let mut events_guard = events_ptr.lock().unwrap();
    let events = events_guard.borrow_mut();
    let res = Body::from_json(&ResBody::build_event_dump(events)).unwrap();
    Ok(res.into())
}

///Uses the [`UserClient`] to fetch the newly issued or reissued coins
async fn fetch(client: Arc<UserClient>, events: Arc<Mutex<Vec<ResBody>>>) {
    match client.fetch_all_coins().await {
        Ok(_) => {
            (*events.lock().unwrap()).push(ResBody::build_event("succsessfull fetch".to_owned()))
        }
        Err(e) => (*events.lock().unwrap()).push(ResBody::build_event(format!("{:?}", e))),
    }
}
