use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::util::handle_version_hash_command;
use fedimint_gateway_common::V1_API_ENDPOINT;
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use fedimint_logging::TracingSetup;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::cli::FaucetOpts;
use crate::envs::FM_CLIENT_DIR_ENV;
use crate::util::ProcessManager;
use crate::{Gatewayd, LightningNode};

#[derive(Clone)]
pub struct Faucet {
    #[allow(unused)]
    bitcoin: Arc<bitcoincore_rpc::Client>,
    gw_ldk: Gatewayd,
}

impl Faucet {
    pub async fn new(process_manager: &ProcessManager, opts: &FaucetOpts) -> anyhow::Result<Self> {
        let url = opts.bitcoind_rpc.parse()?;
        let (host, auth) = fedimint_bitcoind::bitcoincore::from_url_to_url_auth(&url)?;
        let bitcoin = Arc::new(bitcoincore_rpc::Client::new(&host, auth)?);
        let gw_ldk = Gatewayd::new(process_manager, LightningNode::Ldk).await?;
        Ok(Faucet { bitcoin, gw_ldk })
    }

    async fn pay_invoice(&self, invoice: String) -> anyhow::Result<()> {
        self.gw_ldk
            .pay_invoice(Bolt11Invoice::from_str(&invoice).expect("Could not parse invoice"))
            .await?;
        Ok(())
    }

    async fn generate_invoice(&self, amount: u64) -> anyhow::Result<String> {
        Ok(self.gw_ldk.create_invoice(amount).await?.to_string())
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

pub async fn run(process_mgr: &ProcessManager, opts: FaucetOpts) -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    handle_version_hash_command(fedimint_build_code_version_env!());

    let faucet = Faucet::new(process_mgr, &opts).await?;
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
