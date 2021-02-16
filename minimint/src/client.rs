use crate::mint::{Coin, CoinNonce, RequestId, SigResponse, SignRequest};
use musig;
use rand::{CryptoRng, RngCore};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;

type IssuanceId = u64;

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
    coins: Vec<CoinRequest>,
    /// Request id
    id: IssuanceId,
}

/// Represents a coin that can be spent by us (i.e. we can sign a transaction with the secret key
/// belonging to the nonce.
pub struct SpendableCoin {
    pub coin: Coin,
    pub spend_key: musig::SecKey,
}

impl RequestId for IssuanceRequest {
    fn id(&self) -> u64 {
        self.id
    }
}

impl IssuanceRequest {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new(amount: usize, mut rng: impl RngCore + CryptoRng) -> (IssuanceRequest, SignRequest) {
        let (requests, blinded_nonces): (Vec<_>, _) =
            (0..amount).map(|_| CoinRequest::new(&mut rng)).unzip();

        let sig_req = SignRequest(blinded_nonces);
        let issuance_req = IssuanceRequest {
            coins: requests,
            id: sig_req.id(),
        };

        (issuance_req, sig_req)
    }

    /// Finalize the issuance request using a [`SigResponse`] from the mint containing the blind
    /// signatures for all coins in this `IssuanceRequest`. It also takes the mint's
    /// [`AggregatePublicKey`] to validate the supplied blind signatures.
    pub fn finalize(
        &self,
        bsigs: SigResponse,
        mint_pub_key: AggregatePublicKey,
    ) -> Result<Vec<SpendableCoin>, CoinFinalizationError> {
        if bsigs.id() != self.id() {
            return Err(CoinFinalizationError::InvalidIssuanceId(
                self.id(),
                bsigs.id(),
            ));
        }

        self.coins
            .iter()
            .zip(bsigs.1)
            .enumerate()
            .map(|(idx, (coin_req, bsig))| {
                let sig = unblind_signature(coin_req.blinding_key, bsig);
                let coin = Coin(coin_req.nonce.clone(), sig);
                if coin.verify(mint_pub_key) {
                    Ok(SpendableCoin {
                        coin,
                        spend_key: coin_req.spend_key.clone(),
                    })
                } else {
                    Err(CoinFinalizationError::InvalidSignature(idx))
                }
            })
            .collect()
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
    #[error("Expected {0} blind signatures, got {1}")]
    WrongSignatureCount(usize, usize),
    #[error("The blind signature at index {0} is invalid")]
    InvalidSignature(usize),
    #[error("Expected signatures for issuance request {0}, got signatures for request {1}")]
    InvalidIssuanceId(IssuanceId, IssuanceId),
}
