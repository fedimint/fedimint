use bitcoin_hashes::hex::ToHex;
use minimint::config::load_from_file;
use mint_client::clients::user::{APIResponse, PegInReq, PegOutReq};
use mint_client::rpc::{Request, Response, Router, Shared};
use mint_client::{ClientAndGatewayConfig, UserClient};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
        .add_handler("pegin_address", pegin_address)
        .add_handler("pegin", pegin)
        .add_handler("pegout", pegout);
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
