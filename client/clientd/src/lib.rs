use anyhow::Result;
use async_trait::async_trait;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, RequestParts};
use axum::response::{IntoResponse, Response};
use axum::BoxError;
use bitcoin::hashes::hex::ToHex;
use bitcoin::Transaction;
use fedimint_api::{Amount, OutPoint, TransactionId};
use fedimint_core::modules::mint::tiered::coins::Coins;
use fedimint_core::modules::wallet::txoproof::TxOutProof;
use mint_client::mint::{CoinFinalizationData, SpendableCoin};
use mint_client::ClientError;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientdError {
    #[error("Client error: {0}")]
    ClientError(#[from] ClientError),
    #[error("Fatal server error, action reqired")]
    ServerError,
}

impl IntoResponse for ClientdError {
    fn into_response(self) -> Response {
        let payload = json!({ "error": self.to_string(), });
        let code = match self {
            ClientdError::ClientError(_) => StatusCode::BAD_REQUEST,
            ClientdError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Result::<(), _>::Err((code, axum::Json(payload))).into_response()
    }
}
/// struct to process wait_block_height request payload
#[derive(Deserialize, Serialize)]
pub struct WaitBlockHeightPayload {
    pub height: u64,
}

/// Struct used with the axum json-extractor to proccess the peg_in request payload
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PegInPayload {
    pub txout_proof: TxOutProof,
    pub transaction: Transaction,
}

#[derive(Deserialize, Serialize)]
pub struct SpendPayload {
    pub amount: Amount,
}

#[derive(Deserialize, Serialize)]
pub struct InfoResponse {
    coins: Vec<CoinsByTier>,
    pending: PendingResponse,
}

impl InfoResponse {
    pub fn new(
        coins: Coins<SpendableCoin>,
        active_issuances: Vec<(OutPoint, CoinFinalizationData)>,
    ) -> Self {
        let info_coins: Vec<CoinsByTier> = coins
            .coins
            .iter()
            .map(|(tier, c)| CoinsByTier {
                quantity: c.len(),
                tier: tier.milli_sat,
            })
            .collect();
        Self {
            coins: info_coins,
            pending: PendingResponse::new(active_issuances),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct PendingResponse {
    transactions: Vec<PendingTransaction>,
}

impl PendingResponse {
    pub fn new(active_issuances: Vec<(OutPoint, CoinFinalizationData)>) -> Self {
        let transactions: Vec<PendingTransaction> = active_issuances
            .iter()
            .map(|(out_point, cfd)| PendingTransaction {
                txid: out_point.txid.to_hex(),
                qty: cfd.coin_count(),
                value: cfd.coin_amount(),
            })
            .collect();
        Self { transactions }
    }
}

#[derive(Deserialize, Serialize)]
pub struct PegInAddressResponse {
    pub peg_in_address: bitcoin::Address,
}

#[derive(Deserialize, Serialize)]
pub struct PegInOutResponse {
    pub txid: TransactionId,
}

#[derive(Deserialize, Serialize)]
pub struct SpendResponse {
    pub coins: Coins<SpendableCoin>,
}

/// Holds a e-cash tier (msat by convention) and a quantity of coins
///
/// e.g { tier: 1000, quantity: 10 } means 10x coins worth 1000msat each
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoinsByTier {
    tier: u64,
    quantity: usize,
}

/// Holds a pending transaction with the txid, the quantity of coins and the value
///
/// e.g { txid: xxx, qty: 10, value: 1 } is a pending transaction 'worth' 10btc
/// notice that this are ALL pending transactions not only the ['Accepted'](fedimint_core::outcome::TransactionStatus) ones !
#[derive(Deserialize, Serialize)]
pub struct PendingTransaction {
    txid: String,
    qty: usize,
    value: Amount,
}

pub async fn call<P>(params: &P, enpoint: &str) -> Result<serde_json::Value>
where
    P: Serialize + ?Sized,
{
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://127.0.0.1:8081{}", enpoint))
        .json(params)
        .send()
        .await?;
    Ok(response.json().await?)
}

// We need our own `Json` extractor that customizes the error from `axum::Json`
pub struct Json<T>(pub T);

#[async_trait]
impl<B, T> FromRequest<B> for Json<T>
where
    T: DeserializeOwned + Send,
    B: axum::body::HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = (StatusCode, axum::Json<Value>);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req).await {
            Ok(value) => Ok(Self(value.0)),
            // convert the error from `axum::Json` into whatever we want
            Err(rejection) => {
                let payload = json!({
                    "error": rejection.to_string(),
                });

                let code = match rejection {
                    JsonRejection::JsonDataError(_) => StatusCode::UNPROCESSABLE_ENTITY,
                    JsonRejection::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
                    JsonRejection::MissingJsonContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                Err((code, axum::Json(payload)))
            }
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! json_success {
    () => {
        {
       let body = serde_json::json!({
            "data": {}
       });

       Ok(axum::Json(body))
        }
    };
    ($payload:expr) => {
        {
       let body = serde_json::json!({
            "data": $payload
       });

       Ok(axum::Json(body))
    }
    };
}
