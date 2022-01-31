mod db;

use crate::api::{ApiError, FederationApi};
use bitcoin::schnorr::KeyPair;
use db::{CoinKey, CoinKeyPrefix, OutputFinalizationKey, OutputFinalizationKeyPrefix};
use minimint::modules::mint;
use minimint::modules::mint::tiered::coins::Coins;
use minimint::modules::mint::{
    BlindToken, Coin, CoinNonce, InvalidAmountTierError, Keys, SigResponse, SignRequest,
};
use minimint_api::db::batch::{BatchItem, BatchTx};
use minimint_api::db::{Database, RawDatabase};
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{Amount, OutPoint, TransactionId};
use rand::{CryptoRng, Rng, RngCore};
use reqwest::StatusCode;
use secp256k1_zkp::{Secp256k1, Signing};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;
use tracing::{debug, trace};

/// Federation module client for the Mint module. It can both create transaction inputs and outputs
/// of the mint type.
pub struct MintClient {
    pub db: Arc<dyn RawDatabase>,
    pub cfg: mint::config::MintClientConfig,
    pub api: FederationApi,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
}

/// Client side representation of one coin in an issuance request that keeps all necessary
/// information to generate one spendable coin once the blind signature arrives.
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinRequest {
    /// Spend key from which the coin nonce (corresponding public key) is derived
    spend_key: [u8; 32], // FIXME: either make KeyPair Serializable or add secret key newtype
    /// Nonce belonging to the secret key
    nonce: CoinNonce,
    /// Key to unblind the blind signature supplied by the mint for this coin
    blinding_key: BlindingKey,
}

/// Client side representation of a coin reissuance that keeps all necessary information to
/// generate spendable coins once the blind signatures arrive.
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct CoinFinalizationData {
    /// Finalization data for all coin outputs in this request
    coins: Coins<CoinRequest>,
}

/// Represents a coin that can be spent by us (i.e. we can sign a transaction with the secret key
/// belonging to the nonce.
#[derive(Debug, Clone, Deserialize, Serialize, Encodable, Decodable)]
pub struct SpendableCoin {
    pub coin: Coin,
    pub spend_key: [u8; 32],
}

impl MintClient {
    pub fn coins(&self) -> Coins<SpendableCoin> {
        self.db
            .find_by_prefix::<_, CoinKey, SpendableCoin>(&CoinKeyPrefix)
            .map(|res| {
                let (key, spendable_coin) = res.expect("DB error");
                (key.amount, spendable_coin)
            })
            .collect()
    }

    // FIXME: implement three step process: unspent -> in flight -> spent/unspent
    pub fn mark_coins_spent(&self, mut batch: BatchTx, coins: &Coins<SpendableCoin>) {
        batch.append_from_iter(coins.iter().map(|(amount, coin)| {
            BatchItem::delete(CoinKey {
                amount,
                nonce: coin.coin.0.clone(),
            })
        }));
        batch.commit();
    }

    pub fn select_and_spend_coins(
        &self,
        mut batch: BatchTx,
        amount: Amount,
    ) -> Result<Coins<SpendableCoin>> {
        let coins = self
            .coins()
            .select_coins(amount)
            .ok_or(MintClientError::NotEnoughCoins)?;

        // mark spent in DB
        // TODO: make contingent on success of payment
        self.mark_coins_spent(batch.subtransaction(), &coins);
        batch.commit();
        Ok(coins)
    }

    // TODO: implement input generation with change to avoid error on missing coin denominations
    /// Select coins to fund a transaction with.
    ///
    /// **ATTENTION**: calling this function multiple times without committing the batch to the
    /// database is not supported and will result in an accidental double spend.
    pub fn create_coin_input(
        &self,
        mut batch: BatchTx,
        amount: Amount,
    ) -> Result<(Vec<KeyPair>, Coins<Coin>)> {
        let coins = self.select_and_spend_coins(batch.subtransaction(), amount)?;
        let (spend_keys, coins) = self.create_coin_input_from_coins(coins)?;
        batch.commit();
        Ok((spend_keys, coins))
    }

    pub fn create_coin_input_from_coins(
        &self,
        coins: Coins<SpendableCoin>,
    ) -> Result<(Vec<KeyPair>, Coins<Coin>)> {
        let coin_key_pairs = coins
            .into_iter()
            .map(|(amt, coin)| {
                let spend_key = secp256k1_zkp::schnorrsig::KeyPair::from_seckey_slice(
                    &self.secp,
                    &coin.spend_key,
                )
                .map_err(|_| MintClientError::ReceivedUspendableCoin)?;

                // We check for coin validity in case we got it from an untrusted third party. We
                // don't want to needlessly create invalid tx and bother the federation with them.
                let spend_pub_key =
                    secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&self.secp, &spend_key);
                if &spend_pub_key == coin.coin.spend_key() {
                    Ok((spend_key, (amt, coin.coin)))
                } else {
                    Err(MintClientError::ReceivedUspendableCoin)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(coin_key_pairs.into_iter().unzip())
    }

    pub fn create_coin_output<R: Rng + CryptoRng>(
        &self,
        amount: Amount,
        mut rng: R,
    ) -> (CoinFinalizationData, Coins<BlindToken>) {
        let (coin_finalization_data, sig_req) =
            CoinFinalizationData::new(amount, &self.cfg.tbs_pks, &self.secp, &mut rng);

        let coin_output = sig_req
            .0
            .into_iter()
            .map(|(amt, token)| (amt, BlindToken(token)))
            .collect();

        (coin_finalization_data, coin_output)
    }

    // TODO: find a way to make output creation one-step
    /// We currently need the outpoint as part of coin finalization data. This necessitates to call
    /// this function after the entire transaction was created and prevents us from saving it in
    /// `create_coin_output` where it belongs.  
    pub fn save_coin_finalization_data(
        &self,
        mut batch: BatchTx,
        out_point: OutPoint,
        coin_finalization_data: CoinFinalizationData,
    ) {
        batch.append_insert_new(OutputFinalizationKey(out_point), coin_finalization_data);
        batch.commit()
    }

    pub async fn fetch_coins(&self, mut batch: BatchTx<'_>, outpoint: OutPoint) -> Result<()> {
        let issuance = self
            .db
            .get_value::<_, CoinFinalizationData>(&OutputFinalizationKey(outpoint))
            .expect("DB error")
            .ok_or(MintClientError::FinalizationError(
                CoinFinalizationError::UnknownIssuance,
            ))?;

        let bsig = self
            .api
            .fetch_output_outcome::<Option<SigResponse>>(outpoint)
            .await?
            .ok_or(MintClientError::OutputNotReadyYet(outpoint))?;

        let coins = issuance.finalize(bsig, &self.cfg.tbs_pks)?;

        batch.append_from_iter(
            coins
                .into_iter()
                .map(|(amount, coin): (Amount, SpendableCoin)| {
                    let key = CoinKey {
                        amount,
                        nonce: coin.coin.0.clone(),
                    };
                    let value = coin;
                    BatchItem::insert_new(key, value)
                }),
        );
        batch.append_delete(OutputFinalizationKey(outpoint));
        batch.commit();

        Ok(())
    }

    pub async fn fetch_all_coins(&self, mut batch: BatchTx<'_>) -> Result<Vec<TransactionId>> {
        let active_issuances = self
            .db
            .find_by_prefix::<_, OutputFinalizationKey, CoinFinalizationData>(
                &OutputFinalizationKeyPrefix,
            )
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("DB error");

        // TODO: return out points instead
        let mut tx_ids = vec![];
        for (OutputFinalizationKey(out_point), _) in active_issuances {
            loop {
                match self.fetch_coins(batch.subtransaction(), out_point).await {
                    Ok(()) => {
                        tx_ids.push(out_point.txid);
                        break;
                    }
                    // TODO: make mint error more expressive (currently any HTTP error) and maybe use custom return type instead of error for retrying
                    Err(e) if e.is_retryable_fetch_coins() => {
                        trace!("Mint returned retryable error: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        batch.commit();
        Ok(tx_ids)
    }
}

impl CoinFinalizationData {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new<K, C>(
        amount: Amount,
        amount_tiers: &Keys<K>,
        ctx: &Secp256k1<C>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (CoinFinalizationData, SignRequest)
    where
        C: Signing,
    {
        let (requests, blinded_nonces): (Coins<_>, Coins<_>) =
            Coins::represent_amount(amount, amount_tiers)
                .into_iter()
                .map(|(amt, ())| {
                    let (request, blind_msg) = CoinRequest::new(ctx, &mut rng);
                    ((amt, request), (amt, blind_msg))
                })
                .unzip();

        debug!(
            "Generated issuance request for {} ({} coins, tiers {:?})",
            amount,
            requests.coin_count(),
            requests.coins.keys().collect::<Vec<_>>()
        );

        let sig_req = SignRequest(blinded_nonces);
        let issuance_req = CoinFinalizationData { coins: requests };

        (issuance_req, sig_req)
    }

    /// Finalize the issuance request using a [`SigResponse`] from the mint containing the blind
    /// signatures for all coins in this `IssuanceRequest`. It also takes the mint's
    /// [`AggregatePublicKey`] to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: SigResponse,
        mint_pub_key: &Keys<AggregatePublicKey>,
    ) -> std::result::Result<Coins<SpendableCoin>, CoinFinalizationError> {
        if !self.coins.structural_eq(&bsigs.0) {
            return Err(CoinFinalizationError::WrongMintAnswer);
        }

        self.coins
            .iter()
            .zip(bsigs.0)
            .enumerate()
            .map(|(idx, ((amt, coin_req), (_amt, bsig)))| {
                let sig = unblind_signature(coin_req.blinding_key, bsig);
                let coin = Coin(coin_req.nonce.clone(), sig);
                if coin.verify(*mint_pub_key.tier(&amt)?) {
                    let coin = SpendableCoin {
                        coin,
                        spend_key: coin_req.spend_key,
                    };

                    Ok((amt, coin))
                } else {
                    Err(CoinFinalizationError::InvalidSignature(idx))
                }
            })
            .collect()
    }

    pub fn coin_count(&self) -> usize {
        self.coins.coins.values().map(|v| v.len()).sum()
    }
}

impl CoinRequest {
    /// Generate a request session for a single coin and returns it plus the corresponding blinded
    /// message
    fn new<C>(
        ctx: &Secp256k1<C>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (CoinRequest, BlindedMessage)
    where
        C: Signing,
    {
        let spend_key = secp256k1_zkp::schnorrsig::KeyPair::new(ctx, &mut rng);
        let nonce = CoinNonce(secp256k1_zkp::schnorrsig::PublicKey::from_keypair(
            ctx, &spend_key,
        ));

        let (blinding_key, blinded_nonce) = blind_message(nonce.to_message());

        let cr = CoinRequest {
            spend_key: spend_key.serialize_secret(),
            nonce,
            blinding_key,
        };

        (cr, blinded_nonce)
    }
}

type Result<T> = std::result::Result<T, MintClientError>;

#[derive(Error, Debug)]
pub enum CoinFinalizationError {
    #[error("The returned answer does not fit the request")]
    WrongMintAnswer,
    #[error("The blind signature at index {0} is invalid")]
    InvalidSignature(usize),
    #[error("Expected signatures for issuance request {0}, got signatures for request {1}")]
    InvalidIssuanceId(TransactionId, TransactionId),
    #[error("Invalid amount tier {0:?}")]
    InvalidAmountTier(Amount),
    #[error("The client does not know this issuance")]
    UnknownIssuance,
}

#[derive(Error, Debug)]
pub enum MintClientError {
    #[error("Error querying federation: {0}")]
    ApiError(ApiError),
    #[error("Could not finalize issuance request: {0}")]
    FinalizationError(CoinFinalizationError),
    #[error("The client's wallet has not enough coins or they are not in the right denomination")]
    NotEnoughCoins,
    #[error("The transaction outcome received from the mint did not contain a result for output {0} yet")]
    OutputNotReadyYet(OutPoint),
    #[error("The transaction outcome returned by the mint contains too few outputs (output {0})")]
    InvalidOutcomeWrongStructure(OutPoint),
    #[error("The transaction outcome returned by the mint has an invalid type (output {0})")]
    InvalidOutcomeType(OutPoint),
    #[error("One of the coins meant to be spent is unspendable")]
    ReceivedUspendableCoin,
}

impl MintClientError {
    pub fn is_retryable_fetch_coins(&self) -> bool {
        match self {
            MintClientError::ApiError(ApiError::HttpError(e)) => {
                e.status() == Some(StatusCode::NOT_FOUND)
            }
            MintClientError::OutputNotReadyYet(_) => true,
            _ => false,
        }
    }
}

impl From<ApiError> for MintClientError {
    fn from(e: ApiError) -> Self {
        MintClientError::ApiError(e)
    }
}

impl From<CoinFinalizationError> for MintClientError {
    fn from(e: CoinFinalizationError) -> Self {
        MintClientError::FinalizationError(e)
    }
}

impl From<InvalidAmountTierError> for CoinFinalizationError {
    fn from(e: InvalidAmountTierError) -> Self {
        CoinFinalizationError::InvalidAmountTier(e.0)
    }
}
