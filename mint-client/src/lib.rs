use mint_api::{Amount, Coin, CoinNonce, Coins, SigResponse, SignRequest, TransactionId};
use rand::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;
use tracing::debug;

/// Client side representation of one coin in an issuance request that keeps all necessary
/// information to generate one spendable coin once the blind signature arrives.
pub struct CoinRequest {
    /// Spend key from which the coin nonce (corresponding public key) is derived
    spend_key: musig::SecKey,
    /// Nonce belonging to the secret key
    nonce: CoinNonce,
    /// Key to unblind the blind signature supplied by the mint for this coin
    blinding_key: BlindingKey,
}

/// Client side representation of an issuance request that keeps all necessary information to
/// generate spendable coins once the blind signatures arrive.
pub struct IssuanceRequest {
    /// All coins in this request
    coins: Coins<CoinRequest>,
}

/// Represents a coin that can be spent by us (i.e. we can sign a transaction with the secret key
/// belonging to the nonce.
pub struct SpendableCoin {
    pub coin: Coin,
    pub spend_key: musig::SecKey,
}

impl IssuanceRequest {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new(
        amount: Amount,
        amount_tiers: &BTreeSet<Amount>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (IssuanceRequest, SignRequest) {
        let (requests, blinded_nonces): (Coins<_>, Coins<_>) =
            Coins::represent_amount(amount, amount_tiers)
                .into_iter()
                .map(|(amt, ())| {
                    let (request, blind_msg) = CoinRequest::new(&mut rng);
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
        let issuance_req = IssuanceRequest { coins: requests };

        (issuance_req, sig_req)
    }

    /// Finalize the issuance request using a [`SigResponse`] from the mint containing the blind
    /// signatures for all coins in this `IssuanceRequest`. It also takes the mint's
    /// [`AggregatePublicKey`] to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: SigResponse,
        mint_pub_key: &BTreeMap<Amount, AggregatePublicKey>,
    ) -> Result<Coins<SpendableCoin>, CoinFinalizationError> {
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
                if coin.verify(
                    *mint_pub_key
                        .get(&amt)
                        .ok_or(CoinFinalizationError::InvalidAmountTier(amt))?,
                ) {
                    let coin = SpendableCoin {
                        coin,
                        spend_key: coin_req.spend_key.clone(),
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
    fn new(mut rng: impl RngCore + CryptoRng) -> (CoinRequest, BlindedMessage) {
        let spend_key = musig::SecKey::random(musig::rng_adapt::RngAdaptor(&mut rng));
        let nonce = CoinNonce(spend_key.to_public());

        let (blinding_key, blinded_nonce) = blind_message(nonce.to_message());

        let cr = CoinRequest {
            spend_key,
            nonce,
            blinding_key,
        };

        (cr, blinded_nonce)
    }
}

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
}
