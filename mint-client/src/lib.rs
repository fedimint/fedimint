use bitcoin::{Address, Script, Transaction};
use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash as BitcoinHash;
use config::ClientConfig;
use database::batch::{BatchItem, Element};
use database::{
    check_format, BatchDb, BincodeSerialized, Database, DatabaseKey, DatabaseKeyPrefix,
    DecodingError, PrefixSearchable,
};
use futures::future::JoinAll;
use miniscript::DescriptorTrait;
use mint_api::{
    Amount, Coin, CoinNonce, Coins, InvalidAmountTierError, Keys, PegInProof, PegInProofError,
    PegInRequest, PegOutRequest, ReissuanceRequest, SigResponse, SignRequest, TransactionId,
    Tweakable, TxId, TxOutProof,
};
use musig::rng_adapt::RngAdaptor;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use reqwest::{RequestBuilder, StatusCode};
use secp256k1::{All, Secp256k1};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;
use tracing::debug;

pub const DB_PREFIX_COIN: u8 = 0x20;
pub const DB_PREFIX_ISSUANCE: u8 = 0x21;
pub const DB_PREFIX_PEG_IN: u8 = 0x22;

pub struct MintClient<D> {
    cfg: ClientConfig,
    db: D,
    http_client: reqwest::Client, // TODO: use trait object
    secp: Secp256k1<All>,
}

/// Client side representation of one coin in an issuance request that keeps all necessary
/// information to generate one spendable coin once the blind signature arrives.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssuanceRequest {
    /// All coins in this request
    coins: Coins<CoinRequest>,
}

/// Represents a coin that can be spent by us (i.e. we can sign a transaction with the secret key
/// belonging to the nonce.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpendableCoin {
    pub coin: Coin,
    pub spend_key: musig::SecKey,
}

#[derive(Debug, Clone)]
pub struct IssuanceKey {
    issuance_id: TransactionId,
}

#[derive(Debug, Clone)]
pub struct IssuanceKeyPrefix;

#[derive(Debug, Clone)]
pub struct CoinKey {
    amount: Amount,
    nonce: CoinNonce,
}

#[derive(Debug, Clone)]
pub struct CoinKeyPrefix;

#[derive(Debug, Clone)]
pub struct PegInKey {
    peg_in_script: Script,
}

impl<D> MintClient<D>
where
    D: Database + PrefixSearchable + BatchDb + Sync + Unpin,
{
    pub fn new(cfg: ClientConfig, db: D, secp: Secp256k1<All>) -> Self {
        MintClient {
            cfg,
            db,
            http_client: Default::default(),
            secp,
        }
    }

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        transaction: Transaction,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let secret_tweak_key = transaction
            .output
            .iter()
            .find_map(|out| {
                debug!("Output script: {}", out.script_pubkey);
                self.db
                    .get_value::<_, BincodeSerialized<secp256k1::SecretKey>>(&PegInKey {
                        peg_in_script: out.script_pubkey.clone(),
                    })
                    .expect("DB error")
                    .map(|tweak_secret| tweak_secret.into_owned())
            })
            .ok_or(ClientError::NoMatchingPegInFound)?;
        let public_tweak_key = secp256k1::PublicKey::from_secret_key(&self.secp, &secret_tweak_key);

        let peg_in_proof = PegInProof::new(txout_proof, transaction, public_tweak_key)
            .map_err(|e| ClientError::PegInProofError(e))?;

        let utxos = peg_in_proof.get_our_tweaked_txos(&self.secp, &self.cfg.peg_in_descriptor);
        let sats = utxos.iter().map(|(_, amt, _)| amt.as_sat()).sum::<u64>()
            - (self.cfg.per_utxo_fee.as_sat() * utxos.len() as u64);
        let amount = Amount::from_sat(sats);

        let (issuance_request, sig_req) = IssuanceRequest::new(amount, &self.cfg.mint_pk, &mut rng);

        let peg_in_req_sig = {
            let mut hasher = Sha256::engine();
            bincode::serialize_into(&mut hasher, &sig_req).expect("encoding error");
            bincode::serialize_into(&mut hasher, &peg_in_proof).expect("encoding error");
            let hash = Sha256::from_engine(hasher);

            self.secp.sign(&hash.into(), &secret_tweak_key)
        };

        let req = PegInRequest {
            blind_tokens: sig_req,
            proof: peg_in_proof,
            sig: peg_in_req_sig,
        };

        let req_id = req.id();
        let issuance_key = IssuanceKey {
            issuance_id: req_id,
        };
        let issuance_value = BincodeSerialized::borrowed(&issuance_request);
        self.db
            .insert_entry(&issuance_key, &issuance_value)
            .expect("DB error");

        // Try all mints in random order, break early if enough could be reached
        let mut successes: usize = 0;
        for url in self
            .cfg
            .mints
            .choose_multiple(&mut rng, self.cfg.mints.len())
        {
            let res = self
                .http_client
                .put(&format!("{}/issuance/pegin", url))
                .json(&req)
                .send()
                .await
                .expect("API error");

            if res.status() == StatusCode::OK {
                successes += 1;
            }

            if successes >= 2 {
                // TODO: make this max-faulty +1
                break;
            }
        }

        if successes == 0 {
            Err(ClientError::MintError)
        } else {
            Ok(req_id)
        }
    }

    pub async fn fetch(&self, txid: TransactionId) -> Result<(), ClientError> {
        let issuance = self
            .db
            .get_value::<_, BincodeSerialized<IssuanceRequest>>(&IssuanceKey { issuance_id: txid })
            .expect("DB error")
            .ok_or(ClientError::FinalizationError(
                CoinFinalizationError::UnknowinIssuance,
            ))?
            .into_owned();

        let bsig = self
            .query_any_mint::<SigResponse, _>(|client, mint| {
                let url = format!("{}/issuance/{}", mint, txid);
                client.get(&url)
            })
            .await?;
        // TODO: check another mint if the answer was malicious

        let coins = issuance.finalize(bsig, &self.cfg.mint_pk)?;

        let batch = coins
            .into_iter()
            .map(|(amount, coin): (Amount, SpendableCoin)| {
                let key = CoinKey {
                    amount,
                    nonce: coin.coin.0.clone(),
                };
                let value = BincodeSerialized::owned(coin);
                BatchItem::InsertNewElement(Element {
                    key: Box::new(key),
                    value: Box::new(value),
                })
            })
            .chain(std::iter::once(BatchItem::DeleteElement(Box::new(
                IssuanceKey { issuance_id: txid },
            ))))
            .collect::<Vec<_>>();
        self.db.apply_batch(batch.iter()).expect("DB error");

        Ok(())
    }

    async fn query_any_mint<O, F>(&self, query_builder: F) -> Result<O, ClientError>
    where
        F: Fn(&reqwest::Client, &str) -> RequestBuilder,
        O: DeserializeOwned,
    {
        assert!(!self.cfg.mints.is_empty());

        // TODO: add per mint timeout
        let mut requests = self
            .cfg
            .mints
            .iter()
            .map(|mint| query_builder(&self.http_client, mint.as_str()).send())
            .collect::<Vec<_>>();

        loop {
            let select = futures::future::select_all(requests);
            let (res, _, remaining_requests) = select.await;
            requests = remaining_requests;

            match res {
                Ok(resp) => match resp.json().await {
                    Ok(val) => return Ok(val),
                    Err(_) => {
                        if requests.is_empty() {
                            return Err(ClientError::MintError);
                        }
                    }
                },
                Err(_) => {
                    if requests.is_empty() {
                        return Err(ClientError::MintError);
                    }
                }
            }
        }
    }

    pub async fn fetch_all<R: RngCore + CryptoRng>(
        &self,
        mut rng: R,
    ) -> Result<Vec<TransactionId>, ClientError> {
        let chosen_mint = self
            .cfg
            .mints
            .choose(&mut rng)
            .expect("We need at least one mint");

        let fetched = self
            .db
            .find_by_prefix::<_, IssuanceKey, BincodeSerialized<IssuanceRequest>>(
                &IssuanceKeyPrefix,
            )
            .map(|res| {
                let (id, issuance) = res.expect("DB error");
                let id = id.issuance_id;
                let issuance = issuance.into_owned();

                async move {
                    let url = format!("{}/issuance/{}", chosen_mint, id);
                    let response = self
                        .http_client
                        .get(&url)
                        .send()
                        .await
                        .map_err(|_| ClientError::MintError);

                    let signature: SigResponse = match response {
                        Ok(response) if response.status() == StatusCode::OK => {
                            response.json().await.map_err(|_| ClientError::MintError)
                        }
                        _ => Err(ClientError::MintError),
                    }?;

                    Ok::<_, ClientError>((id, issuance.finalize(signature, &self.cfg.mint_pk)?))
                }
            })
            .collect::<JoinAll<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<(TransactionId, Coins<SpendableCoin>)>, ClientError>>()?;

        let ids = fetched.iter().map(|(id, _)| *id).collect::<Vec<_>>();

        let batch = fetched
            .into_iter()
            .flat_map(|(id, coins)| {
                coins
                    .into_iter()
                    .map(|(amount, coin): (Amount, SpendableCoin)| {
                        let key = CoinKey {
                            amount,
                            nonce: coin.coin.0.clone(),
                        };
                        let value = BincodeSerialized::owned(coin);
                        BatchItem::InsertNewElement(Element {
                            key: Box::new(key),
                            value: Box::new(value),
                        })
                    })
                    .chain(std::iter::once(BatchItem::DeleteElement(Box::new(
                        IssuanceKey { issuance_id: id },
                    ))))
            })
            .collect::<Vec<_>>();
        self.db.apply_batch(&batch).expect("DB error");

        Ok(ids)
    }

    pub fn coins(&self) -> Coins<SpendableCoin> {
        self.db
            .find_by_prefix::<_, CoinKey, BincodeSerialized<SpendableCoin>>(&CoinKeyPrefix)
            .map(|res| {
                let (key, value) = res.expect("DB error");
                (key.amount, value.into_owned())
            })
            .collect()
    }

    pub fn spend_coins(&self, coins: &Coins<SpendableCoin>) {
        let batch = coins
            .iter()
            .map(|(amount, coin)| {
                BatchItem::DeleteElement(Box::new(CoinKey {
                    amount,
                    nonce: coin.coin.0.clone(),
                }))
            })
            .collect::<Vec<_>>();

        self.db.apply_batch(&batch).expect("DB error");
    }

    pub async fn reissue<R: RngCore + CryptoRng>(
        &self,
        coins: Coins<SpendableCoin>,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let (issuance_request, sig_req) = IssuanceRequest::new(
            coins.amount(),
            &self.cfg.mint_pk, // TODO: cache somewhere
            &mut rng,
        );

        let (spend_keys, coins): (Vec<_>, Coins<_>) = coins
            .into_iter()
            .map(|(amt, sc)| (sc.spend_key, (amt, sc.coin)))
            .unzip();

        let mut digest = bitcoin_hashes::sha256::Hash::engine();
        bincode::serialize_into(&mut digest, &coins).unwrap();
        bincode::serialize_into(&mut digest, &sig_req).unwrap();
        let rng_adapt = musig::rng_adapt::RngAdaptor(&mut rng);
        let sig = musig::sign(
            bitcoin_hashes::sha256::Hash::from_engine(digest).into_inner(),
            spend_keys.iter(),
            rng_adapt,
        );

        let req = ReissuanceRequest {
            coins,
            blind_tokens: sig_req,
            sig,
        };

        let req_id = req.id();
        let issuance_key = IssuanceKey {
            issuance_id: req_id,
        };
        let issuance_value = BincodeSerialized::borrowed(&issuance_request);
        self.db
            .insert_entry(&issuance_key, &issuance_value)
            .expect("DB error");

        // Try all mints in random order, break early if enough could be reached
        let mut successes: usize = 0;
        for url in self
            .cfg
            .mints
            .choose_multiple(&mut rng, self.cfg.mints.len())
        {
            let res = self
                .http_client
                .put(&format!("{}/issuance/reissue", url))
                .json(&req)
                .send()
                .await
                .expect("API error");

            if res.status() == StatusCode::OK {
                successes += 1;
            }

            if successes >= 2 {
                // TODO: make this max-faulty +1
                break;
            }
        }

        if successes == 0 {
            Err(ClientError::MintError)
        } else {
            Ok(req_id)
        }
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        amt: Amount,
        address: bitcoin::Address,
        mut rng: R,
    ) -> Result<(), ClientError> {
        let coins = self
            .coins()
            .select_coins(amt)
            .ok_or(ClientError::NotEnoughCoins)?;

        self.spend_coins(&coins);

        let (coins, keys): (Coins<Coin>, Vec<musig::SecKey>) = coins
            .into_iter()
            .map(|(amt, coin)| ((amt, coin.coin), coin.spend_key))
            .unzip();

        let mut hasher = Sha256::engine();
        bincode::serialize_into(&mut hasher, &coins).expect("encoding error");
        bincode::serialize_into(&mut hasher, &address).expect("encoding error");
        let hash = Sha256::from_engine(hasher);

        let sig = musig::sign(hash.into_inner(), keys.iter(), RngAdaptor(&mut rng));

        let pegout_req = PegOutRequest {
            address,
            coins,
            sig,
        };

        // Try all mints in random order, break early if enough could be reached
        let mut successes: usize = 0;
        for url in self
            .cfg
            .mints
            .choose_multiple(&mut rng, self.cfg.mints.len())
        {
            let res = self
                .http_client
                .put(&format!("{}/pegout", url))
                .json(&pegout_req)
                .send()
                .await
                .expect("API error");

            if res.status() == StatusCode::OK {
                successes += 1;
            }

            if successes >= 2 {
                // TODO: make this max-faulty +1
                break;
            }
        }

        if successes == 0 {
            Err(ClientError::MintError)
        } else {
            Ok(())
        }
    }

    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, mut rng: R) -> Address {
        let (peg_in_sec_key, peg_in_pub_key) = self.secp.generate_keypair(&mut rng);

        // TODO: check at startup that no bare descriptor is used in config
        // TODO: check if there are other failure cases
        let script = self
            .cfg
            .peg_in_descriptor
            .tweak(&peg_in_pub_key, &self.secp)
            .script_pubkey();
        debug!("Peg-in script: {}", script);
        let address = Address::from_script(&script, self.cfg.network)
            .expect("Script from descriptor should have an address");

        self.db
            .insert_entry(
                &PegInKey {
                    peg_in_script: script,
                },
                &BincodeSerialized::borrowed(&peg_in_sec_key),
            )
            .expect("DB error");

        address
    }
}

impl IssuanceRequest {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new<K>(
        amount: Amount,
        amount_tiers: &Keys<K>,
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
        mint_pub_key: &Keys<AggregatePublicKey>,
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
                if coin.verify(*mint_pub_key.tier(&amt)?) {
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
    #[error("The client does not know this issuance")]
    UnknowinIssuance,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("All mints responded with an error")]
    MintError,
    #[error("Could not finalize issuance request: {0}")]
    FinalizationError(CoinFinalizationError),
    #[error("Could not find an ongoing matching peg-in")]
    NoMatchingPegInFound,
    #[error("Inconsistent peg-in proof: {0}")]
    PegInProofError(PegInProofError),
    #[error("The client's wallet has not enough coins or they are not in the right denomination")]
    NotEnoughCoins,
}

impl From<InvalidAmountTierError> for CoinFinalizationError {
    fn from(e: InvalidAmountTierError) -> Self {
        CoinFinalizationError::InvalidAmountTier(e.0)
    }
}

impl From<CoinFinalizationError> for ClientError {
    fn from(e: CoinFinalizationError) -> Self {
        ClientError::FinalizationError(e)
    }
}

impl DatabaseKeyPrefix for IssuanceKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(DB_PREFIX_ISSUANCE);
        bytes.extend_from_slice(&self.issuance_id[..]);
        bytes
    }
}

impl DatabaseKey for IssuanceKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(IssuanceKey {
            issuance_id: TransactionId::from_slice(check_format(data, DB_PREFIX_ISSUANCE, 32)?)
                .unwrap(),
        })
    }
}

impl DatabaseKeyPrefix for IssuanceKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_ISSUANCE]
    }
}

impl DatabaseKeyPrefix for CoinKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.push(DB_PREFIX_COIN);
        bytes.extend_from_slice(&self.amount.milli_sat.to_be_bytes()[..]);
        bytes.extend_from_slice(&self.nonce.to_bytes());

        bytes
    }
}

impl DatabaseKey for CoinKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 9 {
            Err(DecodingError::wrong_length(9, data.len()))
        } else if data[0] != DB_PREFIX_COIN {
            Err(DecodingError::wrong_prefix(DB_PREFIX_COIN, data[0]))
        } else {
            let mut amount_bytes = [0u8; 8];
            amount_bytes.copy_from_slice(&data[1..9]);
            let amount = Amount {
                milli_sat: u64::from_be_bytes(amount_bytes),
            };

            let nonce = CoinNonce::from_bytes(&data[9..]);

            Ok(CoinKey { amount, nonce })
        }
    }
}

impl DatabaseKeyPrefix for CoinKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_COIN]
    }
}

impl DatabaseKeyPrefix for PegInKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_PEG_IN];
        bytes.extend_from_slice(&self.peg_in_script[..]);
        bytes
    }
}

impl DatabaseKey for PegInKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 1 {
            Err(DecodingError::wrong_length(1, data.len()))
        } else if data[0] != DB_PREFIX_PEG_IN {
            Err(DecodingError::wrong_prefix(DB_PREFIX_PEG_IN, data[0]))
        } else {
            Ok(PegInKey {
                peg_in_script: Script::from(data[1..].to_vec()),
            })
        }
    }
}
