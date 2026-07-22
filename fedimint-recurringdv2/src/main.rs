use std::net::SocketAddr;

use anyhow::{bail, ensure};
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
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
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use fedimint_lnurl::{InvoiceResponse, LnurlResponse, PayResponse, pay_request_tag};
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage, fee_encoded_expiration};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, PaymentFee, RealGatewayConnection, RoutingInfo,
};
use fedimint_lnv2_common::lnurl::LnurlRequest;
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, GatewayApi, MINIMUM_INCOMING_CONTRACT_AMOUNT, tweak,
};
use fedimint_logging::TracingSetup;
use lightning_invoice::Bolt11Invoice;
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
    /// Public base URL under which this service is reachable, e.g.
    /// `https://lnurl.example.com/`
    ///
    /// Used to construct the LNURL-pay callback URLs returned to payers, so it
    /// must be the exact URL payers reach this service at. Should be an
    /// `https` URL in production.
    #[arg(long, env = "FM_API_ADDRESS")]
    api_address: SafeUrl,
}

#[derive(Clone)]
struct AppState {
    api_address: SafeUrl,
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

    if cli_opts.api_address.scheme() != "https" {
        warn!(
            api_address = %cli_opts.api_address,
            "Api address is not an https URL, payers may be exposed to invoice tampering"
        );
    }

    let state = AppState {
        api_address: cli_opts.api_address.clone(),
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

    info!(
        bind_api = %cli_opts.bind_api,
        api_address = %cli_opts.api_address,
        "recurringdv2 started"
    );

    let listener = TcpListener::bind(cli_opts.bind_api).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    format!("recurringdv2 is up and running at {}", state.api_address)
}

async fn pay(
    State(state): State<AppState>,
    Path(payload): Path<String>,
) -> Json<LnurlResponse<PayResponse>> {
    Json(LnurlResponse::Ok(PayResponse {
        callback: state
            .api_address
            .join_path(&format!("invoice/{payload}"))
            .to_string(),
        max_sendable: MAX_SENDABLE_MSAT,
        min_sendable: MIN_SENDABLE_MSAT,
        tag: pay_request_tag(),
        metadata: "[[\"text/plain\", \"Pay to Recurringd\"]]".to_string(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct GetInvoiceParams {
    amount: u64,
}

async fn invoice(
    Path(payload): Path<String>,
    Query(params): Query<GetInvoiceParams>,
    State(state): State<AppState>,
) -> Json<LnurlResponse<InvoiceResponse>> {
    let Ok(request) = decode_prefixed::<LnurlRequest>(FEDIMINT_PREFIX, &payload) else {
        return Json(LnurlResponse::error("Failed to decode payload"));
    };

    if params.amount < MIN_SENDABLE_MSAT || params.amount > MAX_SENDABLE_MSAT {
        return Json(LnurlResponse::error(format!(
            "Amount must be between {} and {}",
            MIN_SENDABLE_MSAT, MAX_SENDABLE_MSAT
        )));
    }

    let (gateway, invoice) = match create_contract_and_fetch_invoice(
        request.federation_id,
        request.recipient_pk,
        request.aggregate_pk,
        request.gateways,
        params.amount,
        3600, // standard expiry time of one hour
        &state.gateway_conn,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Json(LnurlResponse::error(e.to_string()));
        }
    };

    info!(%params.amount, %gateway, "Created invoice");

    Json(LnurlResponse::Ok(InvoiceResponse {
        pr: invoice.clone(),
        verify: Some(
            gateway
                .join_path(&format!("verify/{}", invoice.payment_hash()))
                .to_string(),
        ),
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

    // Encode the gateway fee in the contract expiration so the receiving client
    // can recover it and report the invoice amount in its payment events. These
    // contracts are discovered via the contract stream rather than awaited
    // per-invoice, so a real expiration is not needed here; the bolt11 invoice
    // still carries the real expiry of `expiry_secs`.
    let expiration = fee_encoded_expiration(routing_info.receive_fee.fee(amount).msats);

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
