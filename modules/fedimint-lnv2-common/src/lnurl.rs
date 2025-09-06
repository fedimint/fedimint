use bitcoin::secp256k1::PublicKey;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use lnurl::lnurl::LnUrl;
use serde::{Deserialize, Serialize};
use tpe::AggregatePublicKey;

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct LnurlRequest {
    pub federation_id: FederationId,
    pub recipient_pk: PublicKey,
    pub aggregate_pk: AggregatePublicKey,
    pub gateways: Vec<SafeUrl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnurlResponse {
    pub lnurl: String,
}

pub async fn generate_lnurl(
    recurringd: SafeUrl,
    federation_id: FederationId,
    recipient_pk: PublicKey,
    aggregate_pk: AggregatePublicKey,
    gateways: Vec<SafeUrl>,
) -> anyhow::Result<String> {
    let payload = LnurlRequest {
        federation_id,
        recipient_pk,
        aggregate_pk,
        gateways,
    };

    let response = reqwest::Client::new()
        .post(format!("{recurringd}lnurl"))
        .json(&payload)
        .send()
        .await?
        .json::<LnurlResponse>()
        .await?;

    Ok(LnUrl::from_url(response.lnurl).encode())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub status: String,
    pub settled: bool,
    pub preimage: Option<[u8; 32]>,
}
