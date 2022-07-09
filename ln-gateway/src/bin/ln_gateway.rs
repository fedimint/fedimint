use clap::Parser;
use ln_gateway::{LnGateway, LnGatewayConfig};
use minimint::config::load_from_file;
use minimint::modules::ln::contracts::ContractId;
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::sync::Arc;
use tide::Response;
use tracing::{debug, instrument};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct State {
    gateway: Arc<LnGateway>,
}

#[derive(Parser)]
struct Opts {
    workdir: PathBuf,
}

#[instrument(skip_all, err)]
async fn pay_invoice(mut req: tide::Request<State>) -> tide::Result {
    let rng = OsRng::new().unwrap();
    let contract_id: ContractId = req.body_json().await?;
    let State { ref gateway } = req.state();

    debug!(%contract_id, "Received request to pay invoice");

    let outpoint = gateway
        .pay_invoice(contract_id, rng)
        .await
        .map_err(tide::Error::from_debug)?;

    gateway
        .await_outgoing_contract_claimed(contract_id, outpoint)
        .await?;

    Ok(Response::new(200))
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts = Opts::parse();
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
