use async_trait::async_trait;
use axum::body::HttpBody;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, RequestParts};
use axum::{BoxError, Json};

use serde::{Deserialize, Serialize};

use minimint_core::modules::wallet::txoproof::TxOutProof;
use mint_client::utils::from_hex;

use crate::PeginPayload;

pub mod payload {
    use bitcoin::Transaction;
    use serde::Deserialize;

    use minimint_core::modules::wallet::txoproof::TxOutProof;

    #[derive(Deserialize, Clone, Debug)]
    pub struct PeginPayload {
        pub txout_proof: TxOutProof,
        pub transaction: Transaction,
    }
}

pub mod responses {
    use serde::Serialize;

    use minimint_api::{Amount, TransactionId};
    use minimint_core::modules::mint::tiered::coins::Coins;
    use mint_client::mint::{CoinFinalizationData, SpendableCoin};

    use crate::utils::CoinsByTier;

    #[derive(Serialize)]
    pub struct InfoResponse {
        coins: Vec<CoinsByTier>,
        pending: PendingResponse,
    }

    #[derive(Serialize)]
    pub struct PendingResponse {
        transactions: usize,
        acc_qty_coins: usize,
        acc_val_amount: Amount,
    }

    #[derive(Serialize)]
    pub struct PeginAddressResponse {
        pegin_address: bitcoin::Address,
    }

    #[derive(Serialize)]
    pub struct PegInOutResponse {
        txid: TransactionId,
    }

    #[derive(Serialize)]
    pub struct SpendResponse {
        pub coins: Coins<SpendableCoin>,
    }

    impl InfoResponse {
        pub fn new(coins: Coins<SpendableCoin>, cfd: Vec<CoinFinalizationData>) -> Self {
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
                pending: PendingResponse::new(cfd),
            }
        }
    }

    impl PendingResponse {
        pub fn new(all_pending: Vec<CoinFinalizationData>) -> Self {
            let acc_qty_coins = all_pending.iter().map(|cfd| cfd.coin_count()).sum();
            let acc_val_amount = all_pending.iter().map(|cfd| cfd.coin_amount()).sum();
            Self {
                transactions: all_pending.len(),
                acc_qty_coins,
                acc_val_amount,
            }
        }
    }

    impl PeginAddressResponse {
        pub fn new(pegin_address: bitcoin::Address) -> Self {
            Self { pegin_address }
        }
    }

    impl PegInOutResponse {
        pub fn new(txid: TransactionId) -> Self {
            Self { txid }
        }
    }

    impl SpendResponse {
        pub fn new(coins: Coins<SpendableCoin>) -> Self {
            Self { coins }
        }
    }
}
// Holds quantity of coins per tier
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoinsByTier {
    tier: u64,
    quantity: usize,
}
pub struct JsonDecodeTransaction(pub PeginPayload);
//Alternative for this would be serde_from and impl from raw -> decoded
#[async_trait]
impl<B> FromRequest<B> for JsonDecodeTransaction
where
    B: HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = JsonRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        #[derive(Deserialize, Clone, Debug)]
        pub struct PeginPayloadEncoded {
            pub txout_proof: TxOutProof,
            pub transaction: String,
        }
        let encoded: PeginPayloadEncoded = Json::from_request(req).await?.0;
        let transaction = from_hex(&encoded.transaction).unwrap(); //FIXME: this is bad
        let decoded = super::PeginPayload {
            txout_proof: encoded.txout_proof,
            transaction,
        };
        Ok(Self(decoded))
    }
}
