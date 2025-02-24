use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use cln_rpc::ClnRpc;
use cln_rpc::primitives::{Amount as ClnAmount, AmountOrAny};
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::util::handle_version_hash_command;
use fedimint_gateway_common::V1_API_ENDPOINT;
use fedimint_logging::TracingSetup;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::cli::FaucetOpts;
use crate::envs::FM_CLIENT_DIR_ENV;

#[derive(Clone)]
pub struct Faucet {
    #[allow(unused)]
    bitcoin: Arc<bitcoincore_rpc::Client>,
    ln_rpc: Arc<Mutex<ClnRpc>>,
}

impl Faucet {
    pub async fn new(opts: &FaucetOpts) -> anyhow::Result<Self> {
        let url = opts.bitcoind_rpc.parse()?;
        let (host, auth) = fedimint_bitcoind::bitcoincore::from_url_to_url_auth(&url)?;
        let bitcoin = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);
        let ln_rpc = Arc::new(Mutex::new(
            ClnRpc::new(&opts.cln_socket)
                .await
                .with_context(|| format!("couldn't open CLN socket {}", &opts.cln_socket))?,
        ));
        Ok(Faucet { bitcoin, ln_rpc })
    }

    async fn pay_invoice(&self, invoice: String) -> anyhow::Result<()> {
        let invoice_status = self
            .ln_rpc
            .lock()
            .await
            .call_typed(&cln_rpc::model::requests::PayRequest {
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
                partial_msat: None,
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
            .call_typed(&cln_rpc::model::requests::InvoiceRequest {
                amount_msat: AmountOrAny::Amount(ClnAmount::from_sat(amount)),
                description: "lnd-gw-to-cln".to_string(),
                label: format!("faucet-{}", rand::random::<u64>()),
                expiry: None,
                fallbacks: None,
                preimage: None,
                cltv: None,
                deschashonly: None,
                exposeprivatechannels: None,
            })
            .await?
            .bolt11)
    }
}

fn get_invite_code(invite_code: Option<String>) -> anyhow::Result<String> {
    if let Some(s) = invite_code {
        Ok(s)
    } else {
        let data_dir = std::env::var(FM_CLIENT_DIR_ENV)?;
        Ok(std::fs::read_to_string(
            PathBuf::from(data_dir).join("invite-code"),
        )?)
    }
}

pub async fn run(opts: FaucetOpts) -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    handle_version_hash_command(fedimint_build_code_version_env!());

    let faucet = Faucet::new(&opts).await?;
    let router = Router::new()
        .route(
            "/connect-string",
            get(|| async {
                get_invite_code(opts.invite_code)
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
            get(move || async move {
                format!("http://127.0.0.1:{}/{V1_API_ENDPOINT}", opts.gw_lnd_port)
            }),
        )
        .layer(CorsLayer::permissive())
        .with_state(faucet);

    let listener = TcpListener::bind(&opts.bind_addr).await?;
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}
