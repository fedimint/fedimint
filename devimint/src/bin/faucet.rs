use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use cln_rpc::primitives::{Amount as ClnAmount, AmountOrAny};
use cln_rpc::ClnRpc;
use fedimint_logging::TracingSetup;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(clap::Parser)]
struct Cmd {
    #[clap(long, env = "FM_FAUCET_BIND_ADDR")]
    bind_addr: String,
    #[clap(long, env = "FM_BITCOIND_RPC")]
    bitcoind_rpc: String,
    #[clap(long, env = "FM_CLN_SOCKET")]
    cln_socket: String,
    #[clap(long, env = "FM_CONNECT_STRING")]
    connect_string: String,
}

#[derive(Clone)]
struct Faucet {
    #[allow(unused)]
    bitcoin: Arc<bitcoincore_rpc::Client>,
    ln_rpc: Arc<Mutex<ClnRpc>>,
}

impl Faucet {
    async fn new(cmd: &Cmd) -> anyhow::Result<Self> {
        let url = cmd.bitcoind_rpc.parse()?;
        let (host, auth) = fedimint_bitcoind::bitcoincore_rpc::from_url_to_url_auth(&url)?;
        let bitcoin = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);
        let ln_rpc = Arc::new(Mutex::new(ClnRpc::new(&cmd.cln_socket).await?));
        Ok(Faucet { bitcoin, ln_rpc })
    }

    async fn pay_invoice(&self, invoice: String) -> anyhow::Result<()> {
        let invoice_status = self
            .ln_rpc
            .lock()
            .await
            .call_typed(cln_rpc::model::PayRequest {
                bolt11: invoice,
                amount_msat: None,
                label: None,
                riskfactor: None,
                maxfeepercent: None,
                retry_for: None,
                maxdelay: None,
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                maxfee: None,
                description: None,
            })
            .await?
            .status;

        anyhow::ensure!(
            matches!(invoice_status, cln_rpc::model::PayStatus::COMPLETE),
            "payment not complete"
        );
        Ok(())
    }

    async fn generate_invoice(&self, amount: u64) -> anyhow::Result<String> {
        Ok(self
            .ln_rpc
            .lock()
            .await
            .call_typed(cln_rpc::model::InvoiceRequest {
                amount_msat: AmountOrAny::Amount(ClnAmount::from_sat(amount)),
                description: "lnd-gw-to-cln".to_string(),
                label: format!("faucet-{}", rand::random::<u64>()),
                expiry: None,
                fallbacks: None,
                preimage: None,
                exposeprivatechannels: None,
                cltv: None,
                deschashonly: None,
            })
            .await?
            .bolt11)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;
    let cmd = Cmd::parse();
    let faucet = Faucet::new(&cmd).await?;
    let router = Router::new()
        .route(
            "/connect-string",
            get(|| async move { cmd.connect_string.clone() }),
        )
        .route(
            "/pay",
            post(|State(faucet): State<Faucet>, invoice: String| async move {
                faucet
                    .pay_invoice(invoice)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }),
        )
        .route(
            "/invoice",
            post(|State(faucet): State<Faucet>, amt: String| async move {
                let amt = amt
                    .parse::<u64>()
                    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
                faucet
                    .generate_invoice(amt)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }),
        )
        .layer(CorsLayer::permissive())
        .with_state(faucet);

    axum::Server::bind(&cmd.bind_addr.parse()?)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}
