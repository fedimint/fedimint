use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;
use minimint_api::Amount;
use mint_client::clients::user::{parse_coins, serialize_coins, ResBody, UserClient};
use mint_client::mint::SpendableCoin;
use mint_client::ClientAndGatewayConfig;
use std::borrow::BorrowMut;
use std::{path::PathBuf, sync::Arc, sync::Mutex};
use structopt::StructOpt;
use tide::{Body, Request, Response};

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

/// Endpoint: responds with [`ResBody::Pending`]
async fn pending(req: Request<State>) -> tide::Result {
    let client = &req.state().client;
    let cfd = client.fetch_active_issuances();
    //This will never fail since ResBody is always build with reliable constructors and cant be 'messed up' so unwrap is ok
    let body = Body::from_json(&ResBody::build_pending(cfd)).unwrap();
    Ok(body.into())
}
/// Endpoint: responds with [`ResBody::Spend`]
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
        Ok(outgoing_coins) => ResBody::build_spend(serialize_coins(&outgoing_coins)),
        Err(e) => ResBody::build_event(format!("{:?}", e)),
    };
    //Unwrap ok
    let body = Body::from_json(&res).unwrap();
    Ok(body.into())
}
/// Endpoint: starts a re-issuance and responds with [`ResBody::Reissue`], and fetches in the background
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let value: String = req.body_json().await?; //Approach B
    let client = Arc::clone(&req.state().client);

    let coins: Coins<SpendableCoin> = parse_coins(&value);
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
/// Endpoint: always responds with Status 200. The caller has to be aware that it can fail and might query /event afterwards.
async fn reissue(mut req: Request<State>) -> tide::Result {
    let value: String = req.body_json().await?;
    let client = Arc::clone(&req.state().client);
    let events = Arc::clone(&req.state().events);
    tokio::spawn(async move {
        let coins: Coins<SpendableCoin> = parse_coins(&value);
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
    //Use ResBody::Empty ?
    Ok(Response::new(200))
}

/// Endpoint: responds with [`ResBody::EventDump`]
async fn events(req: Request<State>) -> tide::Result {
    //note : I think if you crtl c in the reissue/fetch process it can breack things (unfetchable "lost coins")
    //had to reset cfg
    let events_ptr = Arc::clone(&req.state().events);
    let mut events_guard = events_ptr.lock().unwrap();
    let events = events_guard.borrow_mut();
    let res = Body::from_json(&ResBody::build_event_dump(events)).unwrap();
    Ok(res.into())
}

async fn fetch(client: Arc<UserClient>, events: Arc<Mutex<Vec<ResBody>>>) {
    match client.fetch_all_coins().await {
        Ok(_) => {
            (*events.lock().unwrap()).push(ResBody::build_event("succsessfull fetch".to_owned()))
        }
        Err(e) => (*events.lock().unwrap()).push(ResBody::build_event(format!("{:?}", e))),
    }
}
