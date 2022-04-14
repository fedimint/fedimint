use minimint::config::load_from_file;
use mint_client::clients::user::APIResponse;
use mint_client::rpc::{Request, Response, Router, Shared};
use mint_client::{ClientAndGatewayConfig, UserClient};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
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
    let router = Router::new().add_handler("info", info);
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
//TODO: implement all other Endpoints
