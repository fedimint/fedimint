use ln_gateway::{LnGateway, LnGatewayConfig};
use minimint::config::load_from_file;
use minimint::modules::ln::contracts::ContractId;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tide::Response;
use tracing::{debug, instrument};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    gateway: Arc<LnGateway>,
}

#[derive(StructOpt)]
struct Opts {
    workdir: PathBuf,
}

#[instrument(skip_all, err)]
async fn pay_invoice(mut req: tide::Request<State>) -> tide::Result {
    let rng = rand::rngs::OsRng::new().unwrap();
    let contract: ContractId = req.body_json().await?;
    let State { ref gateway } = req.state();

    debug!(%contract, "Received request to pay invoice");

    gateway
        .pay_invoice(contract, rng)
        .await
        .map_err(tide::Error::from_debug)
        .map(|()| Response::new(200))
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("gateway.json");
    let db_path = opts.workdir.join("gateway.db");
    let cfg: LnGatewayConfig = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let gateway = LnGateway::from_config(Box::new(db), cfg).await;

    let state = State {
        gateway: Arc::new(gateway),
    };

    let mut app = tide::with_state(state);
    app.at("/pay_invoice").post(pay_invoice);
    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
