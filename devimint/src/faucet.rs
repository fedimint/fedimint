use std::str::FromStr;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use fedimint_gateway_common::V1_API_ENDPOINT;
use fedimint_ln_server::common::lightning_invoice::Bolt11Invoice;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::federation::Federation;
use crate::{DevFed, Gatewayd};

#[derive(Clone)]
pub struct Faucet {
    gw_ldk: Gatewayd,
    fed: Federation,
}

impl Faucet {
    pub fn new(dev_fed: &DevFed) -> Self {
        let gw_ldk = dev_fed.gw_ldk.clone();
        let fed = dev_fed.fed.clone();
        Faucet { gw_ldk, fed }
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

    fn get_invite_code(&self) -> anyhow::Result<String> {
        self.fed.invite_code()
    }
}

pub async fn run(
    dev_fed: &DevFed,
    fauct_bind_addr: String,
    gw_lnd_port: u16,
) -> anyhow::Result<()> {
    let faucet = Faucet::new(dev_fed);
    let router = Router::new()
        .route(
            "/connect-string",
            get(|State(faucet): State<Faucet>| async move {
                faucet
                    .get_invite_code()
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
            get(move || async move { format!("http://127.0.0.1:{gw_lnd_port}/{V1_API_ENDPOINT}") }),
        )
        .layer(CorsLayer::permissive())
        .with_state(faucet);

    let listener = TcpListener::bind(fauct_bind_addr).await?;
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}
