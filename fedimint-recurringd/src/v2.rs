use anyhow::{anyhow, bail, ensure};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{self, PublicKey};
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
use fedimint_lnv2_common::lnurl::{LnurlRequest, LnurlResponse};
use fedimint_lnv2_common::{Bolt11InvoiceDescription, tweak};
use lightning_invoice::Bolt11Invoice;
use lnurl::Tag;
use lnurl::pay::PayResponse;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tpe::AggregatePublicKey;

use crate::encrypt::{Encryptable, EncryptedData};

const MAX_SENDABLE_MSAT: u64 = 100_000_000_000;
const MIN_SENDABLE_MSAT: u64 = 100_000;

#[derive(Clone)]
struct Recurringd {
    base_url: SafeUrl,
    encryption_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct GetInvoiceParams {
    amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct LNURLPayInvoice {
    pr: String,
    verify: String,
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
        let json = Json(serde_json::json!({
            "status": "ERROR",
            "reason": self.reason.to_string(),
        }));

        (self.code, json).into_response()
    }
}

pub fn router(base_url: SafeUrl, encryption_key: String) -> Router {
    let state = Recurringd {
        base_url: base_url.clone(),
        encryption_key: encryption_key
            .consensus_hash::<sha256::Hash>()
            .to_byte_array(),
    };

    Router::new()
        .route("/", get(health_check))
        .route("/lnurl", post(lnv2_register))
        .route("/pay/{payload}", get(lnv2_pay))
        .route("/invoice/{payload}", get(lnv2_invoice))
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    "RecurringdV2 is up and running!"
}

async fn lnv2_register(
    State(state): State<Recurringd>,
    Json(request): Json<LnurlRequest>,
) -> Result<Json<LnurlResponse>, LnurlError> {
    let payload = request.encrypt(&state.encryption_key).encode_base32();

    Ok(Json(LnurlResponse {
        lnurl: format!("{}pay/{}", state.base_url, payload),
    }))
}

async fn lnv2_pay(
    Path(payload): Path<String>,
    State(state): State<Recurringd>,
) -> Result<Json<PayResponse>, LnurlError> {
    let response = PayResponse {
        callback: format!("{}invoice/{payload}", state.base_url),
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

async fn lnv2_invoice(
    Path(payload): Path<String>,
    Query(params): Query<GetInvoiceParams>,
    State(state): State<Recurringd>,
) -> Result<Json<LNURLPayInvoice>, LnurlError> {
    let request: LnurlRequest = EncryptedData::decode_base32(&payload)
        .ok_or(LnurlError::bad_request(anyhow!("Failed to decode payload")))?
        .decrypt(&state.encryption_key)
        .ok_or(LnurlError::bad_request(anyhow!(
            "Failed to decrypt payload"
        )))?;

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
    )
    .await
    .map_err(LnurlError::internal)?;

    Ok(Json(LNURLPayInvoice {
        pr: invoice.to_string(),
        verify: format!("{}/verify/{}", gateway, invoice.payment_hash()),
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn create_contract_and_fetch_invoice(
    federation_id: FederationId,
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    gateways: Vec<SafeUrl>,
    amount: u64,
    expiry_secs: u32,
) -> anyhow::Result<(SafeUrl, Bolt11Invoice)> {
    let (ephemeral_tweak, ephemeral_pk) = tweak::generate(recipient_pk);

    let scalar = Scalar::from_be_bytes(ephemeral_tweak).unwrap();

    let claim_pk = recipient_pk
        .mul_tweak(secp256k1::SECP256K1, &scalar)
        .expect("Tweak is valid");

    let encryption_seed = ephemeral_tweak
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let preimage = encryption_seed
        .consensus_hash::<sha256::Hash>()
        .to_byte_array();

    let (routing_info, gateway) = select_gateway(gateways, federation_id).await?;

    ensure!(
        routing_info.receive_fee.le(&PaymentFee::RECEIVE_FEE_LIMIT),
        "Payment fee exceeds limit"
    );

    let contract_amount = routing_info.receive_fee.subtract_from(amount);

    // The dust limit ensures that the incoming contract can be claimed without
    // additional funds as the contracts amount is sufficient to cover the fees
    ensure!(contract_amount >= Amount::from_sats(5), "Dust amount");

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

    // TODO: Fix me
    /*
    let invoice = RealGatewayConnection
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
    */
    todo!()
}

async fn select_gateway(
    gateways: Vec<SafeUrl>,
    federation_id: FederationId,
) -> anyhow::Result<(RoutingInfo, SafeUrl)> {
    // TODO: Fix me
    /*
    for gateway in gateways {
        if let Ok(Some(routing_info)) = MockGatewayConnection
            .routing_info(gateway.clone(), &federation_id)
            .await
        {
            return Ok((routing_info, gateway));
        }
    }
    */

    bail!("All gateways are offline or do not support this federation")
}
