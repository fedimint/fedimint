use bitcoin::{Address, Script, Transaction};
use bitcoin_hashes::Hash as BitcoinHash;
use config::ClientConfig;
use futures::future::JoinAll;
use miniscript::DescriptorTrait;
use mint_api::db::batch::{BatchItem, DbBatch};
use mint_api::db::{
    check_format, BincodeSerialized, Database, DatabaseKey, DatabaseKeyPrefix, DecodingError,
    RawDatabase,
};
use mint_api::outcome::{Final, OutputOutcome, TransactionStatus};
use mint_api::transaction as mint_tx;
use mint_api::{
    Amount, Coin, CoinNonce, Coins, InvalidAmountTierError, Keys, PegInProof, PegInProofError,
    SigResponse, SignRequest, TransactionId, Tweakable, TxOutProof,
};
use musig::rng_adapt::RngAdaptor;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use reqwest::{RequestBuilder, StatusCode};
use secp256k1::{All, Secp256k1};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::sync::Arc;
use tbs::{blind_message, unblind_signature, AggregatePublicKey, BlindedMessage, BlindingKey};
use thiserror::Error;
use tokio::time::Duration;
use tracing::debug;

pub const DB_PREFIX_COIN: u8 = 0x20;
pub const DB_PREFIX_OUTPUT_FINALIZATION_DATA: u8 = 0x21;
pub const DB_PREFIX_PEG_IN: u8 = 0x22;

pub struct MintClient {
    cfg: ClientConfig,
    db: Arc<dyn RawDatabase>,
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

/// Client side representation of a coin reissuance that keeps all necessary information to
/// generate spendable coins once the blind signatures arrive.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoinFinalizationData {
    /// Finalization data for all coin outputs in this request
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
pub struct OutputFinalizationKey {
    transaction_id: TransactionId,
    output_idx: usize,
}

#[derive(Debug, Clone)]
pub struct OutputFinalizationKeyPrefix;

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

#[derive(Debug, Clone)]
pub struct PegInPrefixKey;

impl MintClient {
    pub fn new(cfg: ClientConfig, db: Arc<dyn RawDatabase>, secp: Secp256k1<All>) -> Self {
        MintClient {
            cfg,
            db,
            http_client: Default::default(),
            secp,
        }
    }

    pub async fn send_tx<R: RngCore>(
        &self,
        tx: mint_tx::Transaction,
        mut rng: R,
    ) -> Result<(), ClientError> {
        // Try all mints in random order, break early if enough could be reached
        let mut successes: usize = 0;
        for url in self
            .cfg
            .mints
            .choose_multiple(&mut rng, self.cfg.mints.len())
        {
            let res = self
                .http_client
                .put(&format!("{}/transaction", url))
                .json(&tx)
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

    pub async fn peg_in<R: RngCore + CryptoRng>(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: Transaction,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let (output_idx, secret_tweak_key) = btc_transaction
            .output
            .iter()
            .enumerate()
            .find_map(|(idx, out)| {
                debug!("Output script: {}", out.script_pubkey);
                self.db
                    .get_value::<_, BincodeSerialized<musig::SecKey>>(&PegInKey {
                        peg_in_script: out.script_pubkey.clone(),
                    })
                    .expect("DB error")
                    .map(|tweak_secret| (idx, tweak_secret.into_owned()))
            })
            .ok_or(ClientError::NoMatchingPegInFound)?;
        let public_tweak_key = secret_tweak_key.to_public();

        let peg_in_proof = PegInProof::new(
            txout_proof,
            btc_transaction,
            output_idx as u32,
            public_tweak_key,
        )
        .map_err(|e| ClientError::PegInProofError(e))?;

        peg_in_proof
            .verify(&self.secp, &self.cfg.peg_in_descriptor)
            .expect("Invalid proof");
        let sats = peg_in_proof.tx_output().value;
        // FIXME: check against underflow
        let amount = Amount::from_sat(sats) - self.cfg.fee_consensus.fee_peg_in_abs;

        let (coin_finalization_data, sig_req) =
            CoinFinalizationData::new(amount, &self.cfg.mint_pk, &mut rng);

        let inputs = vec![mint_tx::Input::PegIn(peg_in_proof)];
        let outputs = vec![mint_tx::Output::Coins(
            sig_req
                .0
                .into_iter()
                .map(|(amt, token)| (amt, mint_tx::BlindToken(token)))
                .collect(),
        )];

        let peg_in_req_sig = {
            let hash = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);
            musig::sign(
                hash.into_inner(),
                [secret_tweak_key].iter(),
                musig::rng_adapt::RngAdaptor(&mut rng),
            )
        };

        let mint_transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature: peg_in_req_sig,
        };

        let tx_id = mint_transaction.tx_hash();
        let issuance_key = OutputFinalizationKey {
            transaction_id: tx_id,
            output_idx: 0,
        };
        let issuance_value = BincodeSerialized::owned(coin_finalization_data);
        self.db
            .insert_entry(&issuance_key, &issuance_value)
            .expect("DB error");

        self.send_tx(mint_transaction, &mut rng).await?;
        Ok(tx_id)
    }

    pub async fn fetch_coins(
        &self,
        txid: TransactionId,
        output_idx: usize,
    ) -> Result<(), ClientError> {
        let issuance = self
            .db
            .get_value::<_, BincodeSerialized<CoinFinalizationData>>(&OutputFinalizationKey {
                transaction_id: txid,
                output_idx,
            })
            .expect("DB error")
            .ok_or(ClientError::FinalizationError(
                CoinFinalizationError::UnknowinIssuance,
            ))?
            .into_owned();

        let tx_outcome = self
            .query_any_mint::<TransactionStatus, _>(|client, mint| {
                let url = format!("{}/transaction/{}", mint, txid);
                client.get(&url)
            })
            .await?;

        // TODO: check another mint if the answer was malicious
        if !tx_outcome.is_final() {
            return Err(ClientError::OutputNotReadyYet(txid, output_idx));
        }

        let outputs = match tx_outcome {
            TransactionStatus::AwaitingConsensus => {
                unreachable!()
            }
            TransactionStatus::Error(e) => {
                panic!("Mint error: {}", e)
            }
            TransactionStatus::Accepted { outputs, .. } => outputs,
        };

        // TODO: remove clone
        let bsig = outputs
            .get(output_idx)
            .and_then(|outcome| match outcome {
                OutputOutcome::Mint(mo) => Some(mo),
                OutputOutcome::Wallet(_) => None,
            })
            .ok_or(ClientError::InvalidOutcomeWrongStructure(txid, output_idx))?
            .clone()
            .ok_or(ClientError::OutputNotReadyYet(txid, output_idx))?;

        let coins = issuance.finalize(bsig, &self.cfg.mint_pk)?;

        let mut batch = DbBatch::new();
        batch.autocommit(|tx| {
            tx.append_from_iter(coins.into_iter().map(
                |(amount, coin): (Amount, SpendableCoin)| {
                    let key = CoinKey {
                        amount,
                        nonce: coin.coin.0.clone(),
                    };
                    let value = BincodeSerialized::owned(coin);
                    BatchItem::insert_new(key, value)
                },
            ));
            tx.append_delete(OutputFinalizationKey {
                transaction_id: txid,
                output_idx,
            });
        });
        self.db.apply_batch(batch).expect("DB error");

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

    pub async fn fetch_all_coins(&self) -> Result<Vec<TransactionId>, ClientError> {
        self.db
            .find_by_prefix::<_, OutputFinalizationKey, BincodeSerialized<CoinFinalizationData>>(
                &OutputFinalizationKeyPrefix,
            )
            .map(|res| {
                let (id, _) = res.expect("DB error");
                async move {
                    loop {
                        match self.fetch_coins(id.transaction_id, id.output_idx).await {
                            Ok(()) => return Ok(id.transaction_id),
                            // TODO: make mint error more expressive (currently any HTTP error) and maybe use custom return type instead of error for retrying
                            Err(ClientError::MintError | ClientError::OutputNotReadyYet(_, _)) => {
                                tokio::time::sleep(Duration::from_secs(1)).await
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            })
            .collect::<JoinAll<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<TransactionId>, ClientError>>()
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
        let mut batch = DbBatch::new();
        batch.autocommit(|tx| {
            tx.append_from_iter(coins.iter().map(|(amount, coin)| {
                BatchItem::delete(CoinKey {
                    amount,
                    nonce: coin.coin.0.clone(),
                })
            }))
        });

        self.db.apply_batch(batch).expect("DB error");
    }

    pub async fn reissue<R: RngCore + CryptoRng>(
        &self,
        coins: Coins<SpendableCoin>,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let (coin_finalization_data, sig_req) = CoinFinalizationData::new(
            coins.amount(),
            &self.cfg.mint_pk, // TODO: cache somewhere
            &mut rng,
        );

        let (spend_keys, coins): (Vec<_>, Coins<_>) = coins
            .into_iter()
            .map(|(amt, coin)| (coin.spend_key, (amt, coin.coin)))
            .unzip();

        let inputs = vec![mint_tx::Input::Coins(coins)];
        let outputs = vec![mint_tx::Output::Coins(sig_req.into())];

        // TODO: abstract away tx building somehow
        let signature = {
            let tx_hash = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);
            let rng_adapt = musig::rng_adapt::RngAdaptor(&mut rng);
            musig::sign(tx_hash.into_inner(), spend_keys.iter(), rng_adapt)
        };

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature,
        };

        let tx_id = transaction.tx_hash();
        let issuance_key = OutputFinalizationKey {
            transaction_id: tx_id,
            output_idx: 0,
        };
        let issuance_value = BincodeSerialized::owned(coin_finalization_data);
        self.db
            .insert_entry(&issuance_key, &issuance_value)
            .expect("DB error");

        self.send_tx(transaction, &mut rng).await?;
        Ok(tx_id)
    }

    pub async fn peg_out<R: RngCore + CryptoRng>(
        &self,
        amt: bitcoin::Amount,
        address: bitcoin::Address,
        mut rng: R,
    ) -> Result<TransactionId, ClientError> {
        let coins = self
            .coins()
            .select_coins(Amount::from(amt) + self.cfg.fee_consensus.fee_peg_out_abs)
            .ok_or(ClientError::NotEnoughCoins)?;

        // mark spent in DB
        // TODO: make contingent on success of payment
        self.spend_coins(&coins);

        let (spend_keys, coins): (Vec<_>, Coins<_>) = coins
            .into_iter()
            .map(|(amt, coin)| (coin.spend_key, (amt, coin.coin)))
            .unzip();

        let inputs = vec![mint_tx::Input::Coins(coins)];
        let outputs = vec![mint_tx::Output::PegOut(mint_tx::PegOut {
            recipient: address,
            amount: amt,
        })];

        let signature = {
            let hash = mint_tx::Transaction::tx_hash_from_parts(&inputs, &outputs);
            musig::sign(hash.into_inner(), spend_keys.iter(), RngAdaptor(&mut rng))
        };

        let transaction = mint_tx::Transaction {
            inputs,
            outputs,
            signature,
        };
        let tx_id = transaction.tx_hash();

        self.send_tx(transaction, &mut rng).await?;
        Ok(tx_id)
    }

    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(&self, mut rng: R) -> Address {
        let peg_in_sec_key = musig::SecKey::random(musig::rng_adapt::RngAdaptor(&mut rng));
        let peg_in_pub_key = peg_in_sec_key.to_public();

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

impl CoinFinalizationData {
    /// Generate a new `IssuanceRequest` and the associates [`SignRequest`]
    pub fn new<K>(
        amount: Amount,
        amount_tiers: &Keys<K>,
        mut rng: impl RngCore + CryptoRng,
    ) -> (CoinFinalizationData, SignRequest) {
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
    #[error("The transaction outcome received from the mint did not contain a result for output {0:}:{1:} yet")]
    OutputNotReadyYet(TransactionId, usize),
    #[error(
        "The transaction outcome returned by the mint contains too few outputs (output {0:}:{1:})"
    )]
    InvalidOutcomeWrongStructure(TransactionId, usize),
    #[error("The transaction outcome returned by the mint has an invalid type (output {0:}:{1:})")]
    InvalidOutcomeType(TransactionId, usize),
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

impl DatabaseKeyPrefix for OutputFinalizationKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(DB_PREFIX_OUTPUT_FINALIZATION_DATA);
        bytes.extend_from_slice(&self.transaction_id[..]);
        bytes.extend_from_slice(&self.output_idx.to_le_bytes());
        bytes
    }
}

impl DatabaseKey for OutputFinalizationKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_OUTPUT_FINALIZATION_DATA, 40)?;

        Ok(OutputFinalizationKey {
            transaction_id: TransactionId::from_slice(&data[0..32]).unwrap(),
            output_idx: usize::from_le_bytes(data[32..].try_into().unwrap()),
        })
    }
}

impl DatabaseKeyPrefix for OutputFinalizationKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_OUTPUT_FINALIZATION_DATA]
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

impl DatabaseKeyPrefix for PegInPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PEG_IN]
    }
}
