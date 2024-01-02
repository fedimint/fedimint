use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
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
    #[clap(long, env = "FM_BITCOIN_RPC_URL")]
    bitcoind_rpc: String,
    #[clap(long, env = "FM_CLN_SOCKET")]
    cln_socket: String,
    #[clap(long, env = "FM_PORT_GW_LND")]
    gw_lnd_port: u16,
    #[clap(long, env = "FM_INVITE_CODE")]
    invite_code: Option<String>,
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
        let (host, auth) = fedimint_bitcoind::bitcoincore::from_url_to_url_auth(&url)?;
        let bitcoin = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);
        let ln_rpc = Arc::new(Mutex::new(
            ClnRpc::new(&cmd.cln_socket)
                .await
                .with_context(|| format!("couldn't open CLN socket {}", &cmd.cln_socket))?,
        ));
        Ok(Faucet { bitcoin, ln_rpc })
    }

    async fn pay_invoice(&self, invoice: String) -> anyhow::Result<()> {
        let invoice_status = self
            .ln_rpc
            .lock()
            .await
            .call_typed(cln_rpc::model::requests::PayRequest {
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
            matches!(
                invoice_status,
                cln_rpc::model::responses::PayStatus::COMPLETE
            ),
            "payment not complete"
        );
        Ok(())
    }

    async fn generate_invoice(&self, amount: u64) -> anyhow::Result<String> {
        Ok(self
            .ln_rpc
            .lock()
            .await
            .call_typed(cln_rpc::model::requests::InvoiceRequest {
                amount_msat: AmountOrAny::Amount(ClnAmount::from_sat(amount)),
                description: "lnd-gw-to-cln".to_string(),
                label: format!("faucet-{}", rand::random::<u64>()),
                expiry: None,
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: None,
            })
            .await?
            .bolt11)
    }
}

fn get_invite_code(invite_code: Option<String>) -> anyhow::Result<String> {
    match invite_code {
        Some(s) => Ok(s),
        None => {
            let data_dir = std::env::var("FM_CLIENT_DIR")?;
            Ok(std::fs::read_to_string(
                PathBuf::from(data_dir).join("invite-code"),
            )?)
        }
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
            get(|| async move {
                get_invite_code(cmd.invite_code)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))
            }),
        )
        .route(
            "/pay",
            post(|State(faucet): State<Faucet>, invoice: String| async move {
                faucet
                    .pay_invoice(invoice)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))
            }),
        )
        .route(
            "/invoice",
            post(|State(faucet): State<Faucet>, amt: String| async move {
                let amt = amt
                    .parse::<u64>()
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("{e:?}")))?;
                faucet
                    .generate_invoice(amt)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))
            }),
        )
        .route(
            "/gateway-api",
            get(move || async move { format!("http://127.0.0.1:{}/v1", cmd.gw_lnd_port) }),
        )
        .layer(CorsLayer::permissive())
        .with_state(faucet);

    axum::Server::bind(&cmd.bind_addr.parse()?)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}
