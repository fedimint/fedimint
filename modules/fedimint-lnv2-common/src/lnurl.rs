use anyhow::{bail, ensure};
use bitcoin::hashes::sha256;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, PublicKey};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::secp256k1::{Scalar, ecdh};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, BitcoinHash};
use lightning_invoice::Bolt11Invoice;
use lnurl::lnurl::LnUrl;
use rand;
use serde::{Deserialize, Serialize};
use tpe::AggregatePublicKey;

use crate::Bolt11InvoiceDescription;
use crate::contracts::{IncomingContract, PaymentImage};
use crate::gateway_api::{
    AwaitBolt11PreimagePayload, GatewayConnection, PaymentFee, RealGatewayConnection, RoutingInfo,
};

#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct LnurlRegistrationRequest {
    pub federation_id: FederationId,
    pub recipient_pk: PublicKey,
    pub aggregate_pk: AggregatePublicKey,
    pub gateways: Vec<SafeUrl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnurlRegistrationResponse {
    pub hash: sha256::Hash,
}

pub async fn register_lnurl(
    recurringd: SafeUrl,
    federation_id: FederationId,
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    gateways: Vec<SafeUrl>,
) -> anyhow::Result<sha256::Hash> {
    let payload = LnurlRegistrationRequest {
        federation_id,
        recipient_pk,
        aggregate_pk,
        gateways,
    };

    let response = reqwest::Client::new()
        .post(format!("{recurringd}lnv2/register"))
        .json(&payload)
        .send()
        .await?
        .json::<LnurlRegistrationResponse>()
        .await?;

    Ok(response.hash)
}

pub fn construct_lnurl(recurringd: &SafeUrl, hash: sha256::Hash) -> String {
    LnUrl::from_url(format!("{recurringd}lnv2/pay/{hash}")).encode()
}

fn generate_ephemeral_tweak(static_pk: PublicKey) -> ([u8; 32], PublicKey) {
    let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let tweak = ecdh::SharedSecret::new(&static_pk, &keypair.secret_key());

    (tweak.secret_bytes(), keypair.public_key())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_contract_and_fetch_invoice(
    federation_id: FederationId,
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    gateways: Vec<SafeUrl>,
    amount: Amount,
    expiry_secs: u32,
) -> anyhow::Result<(SafeUrl, OperationId, Bolt11Invoice)> {
    let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(recipient_pk);

    let claim_pk = recipient_pk
        .mul_tweak(
            secp256k1::SECP256K1,
            &Scalar::from_be_bytes(ephemeral_tweak).unwrap(),
        )
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

    let contract_amount = routing_info.receive_fee.subtract_from(amount.msats);

    // The dust limit ensures that the incoming contract can be claimed without
    // additional funds as the contracts amount is sufficient to cover the fees
    ensure!(contract_amount >= Amount::from_sats(50), "Dust amount");

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

    let invoice = RealGatewayConnection
        .bolt11_invoice(
            gateway.clone(),
            federation_id,
            contract.clone(),
            amount,
            Bolt11InvoiceDescription::Direct("LNURL Payment".to_string()),
            expiry_secs,
        )
        .await?;

    ensure!(
        invoice.payment_hash() == &preimage.consensus_hash(),
        "Invalid invoice payment hash"
    );

    ensure!(
        invoice.amount_milli_satoshis() == Some(amount.msats),
        "Invalid invoice amount"
    );

    Ok((gateway, OperationId::from_encodable(&contract), invoice))
}

async fn select_gateway(
    gateways: Vec<SafeUrl>,
    federation_id: FederationId,
) -> anyhow::Result<(RoutingInfo, SafeUrl)> {
    for gateway in gateways {
        if let Ok(Some(routing_info)) = RealGatewayConnection
            .routing_info(gateway.clone(), &federation_id)
            .await
        {
            return Ok((routing_info, gateway));
        }
    }

    bail!("All gateways are offline or do not support this federation")
}

pub async fn await_bolt11_preimage(
    payment_hash: sha256::Hash,
    federation_id: FederationId,
    operation_id: OperationId,
    gateway: SafeUrl,
) -> anyhow::Result<Option<[u8; 32]>> {
    let payload = AwaitBolt11PreimagePayload {
        federation_id,
        operation_id,
    };

    let response = reqwest::Client::new()
        .post(format!("{gateway}lnv2/await_bolt11_preimage"))
        .json(&payload)
        .send()
        .await?
        .json::<Option<[u8; 32]>>()
        .await?;

    if let Some(preimage) = response {
        ensure!(
            preimage.consensus_hash::<sha256::Hash>() == payment_hash,
            "Gateway returned invalid preimage"
        );
    }

    Ok(response)
}
