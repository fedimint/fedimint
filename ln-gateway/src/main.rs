use clightningrpc::lightningrpc::PayOptions;
use clightningrpc::LightningRPC;
use config::{load_from_file, ClientConfig};
use mint_api::Coins;
use mint_client::{MintClient, SpendableCoin};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use structopt::StructOpt;
use tide::Response;
use tracing::debug;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    coins: Coins<SpendableCoin>,
    invoice: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    ln_socket: String,
    client: ClientConfig,
}

#[derive(Clone)]
pub struct State {
    mint_client: Arc<MintClient>,
    ln_client: Arc<LightningRPC>,
}

async fn pay_invoice(mut req: tide::Request<State>) -> tide::Result {
    let mut rng = rand::rngs::OsRng::new().unwrap();

    let pay_req: PayRequest = req.body_json().await?;
    let invoice = lightning_invoice::Invoice::from_str(&pay_req.invoice)
        .map_err(|e| tide::Error::new(400, e))?;

    let amt_ln_invoice_msat = invoice.amount_pico_btc().expect("no amount given") / 10;
    let amt_coins_msat = pay_req.coins.amount().milli_sat;

    debug!(
        "Received request to pay invoice of {}msat for tokens of value {}msat",
        amt_ln_invoice_msat, amt_coins_msat
    );

    if amt_coins_msat < amt_ln_invoice_msat {
        return Err(tide::Error::from_str(400, "Not enough tokens sent"));
    }

    let State {
        ref mint_client,
        ref ln_client,
    } = req.state();

    debug!("Trying to reissue");
    let tx_id = mint_client
        .reissue(pay_req.coins, &mut rng)
        .await
        .expect("error while starting reissuance");
    debug!("Fetching coins");
    mint_client
        .fetch_coins(tx_id, 0) // TODO: remove assumption about tx structure
        .await
        .map_err(|_| tide::Error::from_str(500, "fetching reissuance failed"))?;

    let invoice = pay_req.invoice;
    let ln_client = ln_client.clone();
    async_std::task::spawn_blocking(move || {
        debug!("Requesting payment from c-lightning");
        ln_client
            .pay(&invoice, PayOptions::default())
            .expect("paying ln invoice failed");
        debug!("Payment succeeded.");
    })
    .await;

    Ok(Response::new(200))
}

#[derive(StructOpt)]
struct Opts {
    workdir: PathBuf,
}

#[tokio::main]
async fn main() -> tide::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts: Opts = StructOpt::from_args();
    let cfg_path = opts.workdir.join("client.json");
    let db_path = opts.workdir.join("client.db");
    let cfg: Config = load_from_file(&cfg_path);
    let db = sled::open(&db_path)
        .unwrap()
        .open_tree("mint-client")
        .unwrap();

    let client = MintClient::new(cfg.client, Arc::new(db), Default::default());
    let ln_client = LightningRPC::new(cfg.ln_socket);

    let state = State {
        mint_client: Arc::new(client),
        ln_client: Arc::new(ln_client),
    };

    let mut app = tide::with_state(state);
    app.at("/").post(pay_invoice);
    app.listen("127.0.0.1:8080").await?;

    Ok(())
}
