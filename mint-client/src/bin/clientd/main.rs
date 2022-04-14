use bitcoin_hashes::hex::ToHex;
use minimint::config::load_from_file;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::outcome::TransactionStatus;
use minimint_api::Amount;
use mint_client::clients::user::{APIResponse, InvoiceReq, PegInReq, PegOutReq, PendingRes};
use mint_client::ln::gateway::LightningGateway;
use mint_client::mint::SpendableCoin;
use mint_client::rpc::{Request, Response, Router, Shared};
use mint_client::{ClientAndGatewayConfig, UserClient};
use reqwest::StatusCode;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use structopt::StructOpt;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    router: Arc<Router>,
    shared: Arc<Shared>,
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
    let router = Router::new()
        .add_handler("info", info)
        .add_handler("pending", pending)
        .add_handler("pegin_address", pegin_address)
        .add_handler("pegin", pegin)
        .add_handler("pegout", pegout)
        .add_handler("spend", spend)
        .add_handler("lnpay", ln_pay)
        .add_handler("reissue", reissue)
        .add_handler("reissue_validate", reissue_validate);
    let shared = Shared {
        client: Arc::new(client),
        gateway: Arc::new(cfg.gateway.clone()),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let state = State {
        router: Arc::new(router),
        shared: Arc::new(shared),
    };
    let mut app = tide::with_state(state);

    app.at("/rpc")
        .post(|mut req: tide::Request<State>| async move {
            //TODO: make shared/router more efficient/logical
            let router = Arc::clone(&req.state().router);
            let shared = Arc::clone(&req.state().shared);
            let req_body: Request = req.body_json().await?;
            let handler_res = router
                .get(req_body.method.as_str())
                .unwrap()
                .call(req_body.params, shared)
                .await;
            let response = Response::with_result(handler_res, req_body.id);
            let body = tide::Body::from_json(&response).unwrap_or_else(|_| tide::Body::empty());
            let mut res = tide::Response::new(200);
            res.set_body(body);
            Ok(res)
        });
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}

async fn info(_: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let client = Arc::clone(&shared.client);
    let cfd = client.fetch_active_issuances();
    let result = APIResponse::build_info(client.coins(), cfd);
    let result = serde_json::json!(&result);
    result
}
async fn pending(_: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let client = &shared.client;
    let cfd = client.fetch_active_issuances();
    let res = serde_json::json!(&APIResponse::Pending {
        pending: PendingRes::build_pending(cfd),
    });
    res
}
async fn pegin_address(_: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let client = Arc::clone(&shared.client);
    // Is it more costly to but rng in shared and always clone or like this ?
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let result = APIResponse::PegInAddress {
        pegin_address: client.get_new_pegin_address(&mut rng),
    };
    let result = serde_json::json!(&result);
    result
}
async fn pegin(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let client = Arc::clone(&shared.client);
    let events = Arc::clone(&shared.events);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let pegin: PegInReq = PegInReq::deserialize(params).unwrap();
    let txout_proof = pegin.txout_proof;
    let transaction = pegin.transaction;
    let id = client
        .peg_in(txout_proof, transaction, &mut rng)
        .await
        .unwrap();
    info!("Started peg-in {}, result will be fetched", id.to_hex());
    tokio::spawn(async move {
        fetch(client, events).await;
    });
    let res = serde_json::json!(&APIResponse::PegIO { txid: id });
    res
}
async fn pegout(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let client = Arc::clone(&shared.client);
    let pegout: PegOutReq = PegOutReq::deserialize(params).unwrap();
    let id = client
        .peg_out(pegout.amount, pegout.address, &mut rng)
        .await
        .unwrap();
    let res = serde_json::json!(&APIResponse::PegIO { txid: id });
    res
}
async fn spend(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let value: u64 = params.as_u64().unwrap();
    let client = &shared.client;
    let amount = Amount::from_sat(value);
    let res = match client.select_and_spend_coins(amount) {
        Ok(outgoing_coins) => APIResponse::build_spend(outgoing_coins),
        Err(e) => APIResponse::build_event(format!("{:?}", e)), //This doesnt make sense right now but will be handled when RPC errors get implemented
    };
    let res = serde_json::json!(&res);
    res
}
async fn ln_pay(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let client = Arc::clone(&shared.client);
    let gateway = Arc::clone(&shared.gateway);
    let invoice: InvoiceReq = InvoiceReq::deserialize(params).unwrap();
    if let Ok(res) = pay_invoice(invoice.bolt11, client, gateway).await {
        match res.status() {
            StatusCode::OK => {
                let res = APIResponse::build_event("succsessfull ln-payment".to_string());
                return serde_json::json!(&res);
            }
            _ => panic!("errors will be handled"),
        }
    } else {
        panic!("errors will be handled");
    }
}
async fn reissue(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let coins: Coins<SpendableCoin> = Coins::deserialize(params).unwrap();
    let client = Arc::clone(&shared.client);
    let events = Arc::clone(&shared.events);
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
    let res = serde_json::json!(&APIResponse::Empty);
    res
}
async fn reissue_validate(params: serde_json::Value, shared: Arc<Shared>) -> serde_json::Value {
    let coins: Coins<SpendableCoin> = Coins::deserialize(params).unwrap();
    let client = Arc::clone(&shared.client);
    let events = Arc::clone(&shared.events);
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let out_point = client.reissue(coins, &mut rng).await.unwrap();
    let status = match client.fetch_tx_outcome(out_point.txid, true).await {
        Err(e) => TransactionStatus::Error(e.to_string()),
        Ok(s) => s,
    };
    let res = serde_json::json!(&APIResponse::build_reissue(out_point, status));
    tokio::spawn(async move {
        fetch(client, events).await;
    });
    res
}
//TODO: implement all other Endpoints
//TODO: almost all unwraps will be handled

///Uses the [`UserClient`] to fetch the newly issued or reissued coins
async fn fetch(client: Arc<UserClient>, events: Arc<Mutex<Vec<APIResponse>>>) {
    match client.fetch_all_coins().await {
        Ok(_) => (*events.lock().unwrap())
            .push(APIResponse::build_event("succsessfull fetch".to_owned())),
        Err(e) => (*events.lock().unwrap()).push(APIResponse::build_event(format!("{:?}", e))),
    }
}

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
