use std::net::SocketAddr;

use anyhow::{anyhow, bail, ensure};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{self, PublicKey};
use clap::Parser;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::base32::{FEDIMINT_PREFIX, decode_prefixed};
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::secp256k1::Scalar;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, PaymentFee, RealGatewayConnection, RoutingInfo,
};
use fedimint_lnv2_common::lnurl::LnurlRequest;
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, GatewayApi, MINIMUM_INCOMING_CONTRACT_AMOUNT, tweak,
};
use fedimint_logging::TracingSetup;
use lightning_invoice::Bolt11Invoice;
use lnurl::Tag;
use lnurl::pay::PayResponse;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors;
use tower_http::cors::CorsLayer;
use tpe::AggregatePublicKey;
use tracing::{info, warn};

const MAX_SENDABLE_MSAT: u64 = 100_000_000_000;
const MIN_SENDABLE_MSAT: u64 = 100_000;

#[derive(Debug, Parser)]
struct CliOpts {
    /// Address to bind the server to
    ///
    /// Should be `0.0.0.0:8176` most of the time, as api connectivity is public
    /// and direct, and the port should be open in the firewall.
    #[arg(long, env = "FM_BIND_API", default_value = "0.0.0.0:8176")]
    bind_api: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    gateway_conn: RealGatewayConnection,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli_opts = CliOpts::parse();

    let connector_registry = ConnectorRegistry::build_from_client_defaults()
        .with_env_var_overrides()?
        .bind()
        .await?;

    let state = AppState {
        gateway_conn: RealGatewayConnection {
            api: GatewayApi::new(None, connector_registry),
        },
    };

    let cors = CorsLayer::new()
        .allow_origin(cors::Any)
        .allow_methods(cors::Any)
        .allow_headers(cors::Any);

    let app = Router::new()
        .route("/", get(health_check))
        .route("/pay/{payload}", get(pay))
        .route("/invoice/{payload}", get(invoice))
        .layer(cors)
        .with_state(state);

    info!(bind_api = %cli_opts.bind_api, "recurringdv2 started");

    let listener = TcpListener::bind(cli_opts.bind_api).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check(headers: HeaderMap) -> impl IntoResponse {
    format!("recurringdv2 is up and running at {}", base_url(&headers))
}

fn base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    format!("{scheme}://{host}/")
}

async fn pay(
    headers: HeaderMap,
    Path(payload): Path<String>,
) -> Result<Json<PayResponse>, LnurlError> {
    let response = PayResponse {
        callback: format!("{}invoice/{payload}", base_url(&headers)),
        max_sendable: MAX_SENDABLE_MSAT,
        min_sendable: MIN_SENDABLE_MSAT,
        tag: Tag::PayRequest,
        metadata: "LNv2 Payment".to_string(),
        comment_allowed: None,
        allows_nostr: None,
        nostr_pubkey: None,
    };

    Ok(Json(response))
}

#[derive(Debug, Serialize, Deserialize)]
struct GetInvoiceParams {
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LnUrlPayInvoiceResponse {
    pr: Bolt11Invoice,
    verify: String,
}

async fn invoice(
    Path(payload): Path<String>,
    Query(params): Query<GetInvoiceParams>,
    State(state): State<AppState>,
) -> Result<Json<LnUrlPayInvoiceResponse>, LnurlError> {
    let request: LnurlRequest = decode_prefixed(FEDIMINT_PREFIX, &payload)
        .map_err(|_| LnurlError::bad_request(anyhow!("Failed to decode payload")))?;

    if params.amount < MIN_SENDABLE_MSAT || params.amount > MAX_SENDABLE_MSAT {
        return Err(LnurlError::bad_request(anyhow!(
            "Amount must be between {} and {}",
            MIN_SENDABLE_MSAT,
            MAX_SENDABLE_MSAT
        )));
    }

    let (gateway, invoice) = create_contract_and_fetch_invoice(
        request.federation_id,
        request.recipient_pk,
        request.aggregate_pk,
        request.gateways,
        params.amount,
        3600, // standard expiry time of one hour
        &state.gateway_conn,
    )
    .await
    .map_err(LnurlError::internal)?;

    info!(%params.amount, %gateway, "Created invoice");

    Ok(Json(LnUrlPayInvoiceResponse {
        pr: invoice.clone(),
        verify: format!("{}/verify/{}", gateway, invoice.payment_hash()),
    }))
}

#[allow(clippy::too_many_arguments)]
async fn create_contract_and_fetch_invoice(
    federation_id: FederationId,
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    gateways: Vec<SafeUrl>,
    amount: u64,
    expiry_secs: u32,
    gateway_conn: &RealGatewayConnection,
) -> anyhow::Result<(SafeUrl, Bolt11Invoice)> {
    let (ephemeral_tweak, ephemeral_pk) = tweak::generate(recipient_pk);

    let scalar = Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order");

    let claim_pk = recipient_pk
        .mul_tweak(secp256k1::SECP256K1, &scalar)
        .expect("Tweak is valid");

    let encryption_seed = ephemeral_tweak
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let preimage = encryption_seed
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let (routing_info, gateway) = select_gateway(gateways, federation_id, gateway_conn).await?;

    ensure!(
        routing_info.receive_fee.le(&PaymentFee::RECEIVE_FEE_LIMIT),
        "Payment fee exceeds limit"
    );

    let contract_amount = routing_info.receive_fee.subtract_from(amount);

    ensure!(
        contract_amount >= MINIMUM_INCOMING_CONTRACT_AMOUNT,
        "Amount too small"
    );

    let expiration = duration_since_epoch()
        .as_secs()
        .saturating_add(u64::from(expiry_secs));

    let contract = IncomingContract::new(
        aggregate_pk,
        encryption_seed,
        preimage,
        PaymentImage::Hash(preimage.consensus_hash()),
        contract_amount,
        expiration,
        claim_pk,
        routing_info.module_public_key,
        ephemeral_pk,
    );

    let invoice = gateway_conn
        .bolt11_invoice(
            gateway.clone(),
            federation_id,
            contract.clone(),
            Amount::from_msats(amount),
            Bolt11InvoiceDescription::Direct("LNURL Payment".to_string()),
            expiry_secs,
        )
        .await?;

    ensure!(
        invoice.payment_hash() == &preimage.consensus_hash(),
        "Invalid invoice payment hash"
    );

    ensure!(
        invoice.amount_milli_satoshis() == Some(amount),
        "Invalid invoice amount"
    );

    Ok((gateway, invoice))
}

async fn select_gateway(
    gateways: Vec<SafeUrl>,
    federation_id: FederationId,
    gateway_conn: &RealGatewayConnection,
) -> anyhow::Result<(RoutingInfo, SafeUrl)> {
    for gateway in gateways {
        if let Ok(Some(routing_info)) = gateway_conn
            .routing_info(gateway.clone(), &federation_id)
            .await
        {
            return Ok((routing_info, gateway));
        }
    }

    bail!("All gateways are offline or do not support this federation")
}

struct LnurlError {
    code: StatusCode,
    reason: anyhow::Error,
}

impl LnurlError {
    fn bad_request(reason: anyhow::Error) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST,
            reason,
        }
    }

    fn internal(reason: anyhow::Error) -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            reason,
        }
    }
}

impl IntoResponse for LnurlError {
    fn into_response(self) -> Response<Body> {
        warn!(reason = %self.reason, "Request failed");

        let json = Json(serde_json::json!({
            "status": "ERROR",
            "reason": self.reason.to_string(),
        }));

        (self.code, json).into_response()
    }
}
