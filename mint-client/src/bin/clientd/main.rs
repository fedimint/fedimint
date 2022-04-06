use bitcoin_hashes::hex::ToHex;
use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;

use minimint_api::Amount;
use mint_client::clients::user::{APIResponse, Event, InvoiceReq, PegInReq, PegOutReq, PendingRes};
use mint_client::ln::gateway::LightningGateway;
use mint_client::mint::SpendableCoin;
use mint_client::{ClientAndGatewayConfig, UserClient};
use reqwest::StatusCode;
use std::borrow::BorrowMut;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use structopt::StructOpt;
use tide::{Body, Request};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    client: Arc<UserClient>,
    gateway: Arc<LightningGateway>,
    events: Arc<Mutex<Vec<APIResponse>>>,
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
        gateway: Arc::new(cfg.gateway.clone()),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let mut app = tide::with_state(state);

    app.at("/info").post(info);
    app.at("/pegin_address").post(pegin_address);
    app.at("pegin").post(pegin);
    app.at("pegout").post(pegout);
    app.at("/spend").post(spend);
    app.at("/lnpay").post(ln_pay);
    app.at("/reissue").post(reissue);
    app.at("/reissue_validate").post(reissue_validate);
    app.at("/pending").post(pending);
    app.at("/events").post(events);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}
/// Endpoint: responds with [`APIResponse::Info`]
async fn info(req: Request<State>) -> tide::Result {
    let client = &req.state().client;
    let cfd = client.fetch_active_issuances();
    let event = Event::Success(APIResponse::build_info(client.coins(), cfd));
    Ok(event.into())
}
/// Endpoint: responds with a [`bitcoin::util::address`], which can be used to peg-in funds to receive e-cash
async fn pegin_address(req: Request<State>) -> tide::Result {
    let client = Arc::clone(&req.state().client);
    let mut rng = rand::rngs::OsRng::new()?; //probably just put that in state later
    let event = Event::Success(APIResponse::PegInAddress {
        pegin_address: client.get_new_pegin_address(&mut rng),
    });
    Ok(event.into())
}
///Endpoint: responds on a successful pegin with a [`minimint_api::TransactionId`] and fetches the e-cash in the background
async fn pegin(mut req: Request<State>) -> tide::Result {
    let client = Arc::clone(&req.state().client);
    let events = Arc::clone(&req.state().events);
    let mut rng = rand::rngs::OsRng::new()?; //probably just put that in state later or something like that
    let pegin: PegInReq = req.body_json().await?;
    let txout_proof = pegin.txout_proof;
    let transaction = pegin.transaction;
    let id = client.peg_in(txout_proof, transaction, &mut rng).await?; //inconsistent (use of '?') but my error handling doesn't make much sense anyway and will be redone
    info!("Started peg-in {}, result will be fetched", id.to_hex());
    tokio::spawn(async move {
        fetch(client, events).await;
    });
    let event = Event::Success(APIResponse::PegIO { txid: id });
    Ok(event.into())
}
///Endpoint: responds with a [`minimint_api::TransactionId`] on a successful pegout
async fn pegout(mut req: Request<State>) -> tide::Result {
    let mut rng = rand::rngs::OsRng::new()?; //probably just put that in state later or something like that
    let client = Arc::clone(&req.state().client);
    let pegout: PegOutReq = req.body_json().await?;
    let id = client
        .peg_out(pegout.amount, pegout.address, &mut rng)
        .await
        .unwrap();
    let event = Event::Success(APIResponse::PegIO { txid: id });
    Ok(event.into())
}
/// Endpoint: responds with [`APIResponse::Spend`], when reissue-ing use everything in the raw json after "token"
async fn spend(mut req: Request<State>) -> tide::Result {
    let value: u64 = match req.body_json().await {
        Ok(i) => i,
        Err(e) => {
            let res = APIResponse::build_event(format!("{:?}", e));
            //Will be always Ok so unwrap is ok
            let body = Body::from_json(&res).unwrap();
            return Ok(body.into());
        }
    };
    let client = &req.state().client;
    let amount = Amount::from_sat(value);
    let res = match client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => APIResponse::build_spend(outgoing_coins),
        Err(e) => APIResponse::build_event(format!("{:?}", e)),
    };
    //Unwrap ok
    let body = Body::from_json(&res).unwrap();
    Ok(body.into())
}
///Endpoint: responds with the [`APIResponse::Event`] variant when successful
async fn ln_pay(mut req: Request<State>) -> tide::Result {
    //TODO: Utilize Errors appropriately (put NotEnoughCoins on EventStack or return directly ?)
    let client = Arc::clone(&req.state().client);
    let gateway = Arc::clone(&req.state().gateway);
    let invoice: InvoiceReq = req.body_json().await?;
    match pay_invoice(invoice.bolt11, client, gateway).await {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let event = Event::Success(APIResponse::build_event(
                    "succsessfull ln-payment".to_string(),
                ));
                Ok(event.into())
            }
            _ => {
                let res = APIResponse::build_event("LN-Payment failed".to_string());
                let error = tide::Error::from_debug(res);
                Err(error) // this dosen't do anything might as well use '?' everywhere since the client only gets 500 error anyway
            }
        },
        Err(e) => {
            let error = tide::Error::from_debug(e);
            Err(error) //same here
        }
    }
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
                    .push(APIResponse::build_event(format!("{:?}", e)));
                return;
            }
        };
        match client.fetch_tx_outcome(out_point.txid, true).await {
            Ok(_) => fetch(client, Arc::clone(&events)).await,
            Err(e) => (*events.lock().unwrap()).push(APIResponse::build_event(format!("{:?}", e))),
        };
    });
    let event = Event::Success(APIResponse::Empty);
    Ok(event.into())
}
/// Endpoint: starts a re-issuance and responds with [`APIResponse::Reissue`], and fetches in the background
async fn reissue_validate(mut req: Request<State>) -> tide::Result {
    let coins: Coins<SpendableCoin> = req.body_json().await?;
    let client = Arc::clone(&req.state().client);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = client.reissue(coins, &mut rng).await?;
    let status = match client.fetch_tx_outcome(out_point.txid, true).await {
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s,
    };
    let event = Event::Success(APIResponse::build_reissue(out_point, status));
    let events = Arc::clone(&req.state().events);
    tokio::spawn(async move {
        fetch(client, events).await;
    });
    Ok(event.into())
}
/// Endpoint: responds with [`PendingRes`]
async fn pending(req: Request<State>) -> tide::Result {
    let client = &req.state().client;
    let cfd = client.fetch_active_issuances();
    let event = Event::Success(APIResponse::Pending {
        pending: PendingRes::build_pending(cfd),
    });
    Ok(event.into())
}
/// Endpoint: responds with [`APIResponse::EventDump`]
async fn events(req: Request<State>) -> tide::Result {
    let events_ptr = Arc::clone(&req.state().events);
    let mut events_guard = events_ptr.lock().unwrap();
    let events = events_guard.borrow_mut();
    let event = Event::Success(APIResponse::build_event_dump(events));
    Ok(event.into())
}

///Uses the [`UserClient`] to fetch the newly issued or reissued coins
async fn fetch(client: Arc<UserClient>, events: Arc<Mutex<Vec<APIResponse>>>) {
    match client.fetch_all_coins().await {
        Ok(_) => (*events.lock().unwrap())
            .push(APIResponse::build_event("succsessfull fetch".to_owned())),
        Err(e) => (*events.lock().unwrap()).push(APIResponse::build_event(format!("{:?}", e))),
    }
}
///Uses the [`UserClient`] to send a Request to the lightning gateway ([`LightningGateway`])
async fn pay_invoice(
    bolt11: lightning_invoice::Invoice,
    client: Arc<UserClient>,
    gateway: Arc<LightningGateway>,
) -> tide::Result<reqwest::Response> {
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let http = reqwest::Client::new();

    let contract_id = client
        .fund_outgoing_ln_contract(&*gateway, bolt11, &mut rng)
        .await?;

    client
        .wait_contract_timeout(contract_id, Duration::from_secs(5))
        .await?;

    info!(
        "Funded outgoing contract {}, notifying gateway",
        contract_id
    );

    Ok(http
        .post(&format!("{}/pay_invoice", &*gateway.api))
        .json(&contract_id)
        .timeout(Duration::from_secs(15))
        .send()
        .await?)
}
