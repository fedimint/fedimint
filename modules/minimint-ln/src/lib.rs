//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust model) interact with
//! the Lightning network through a Lightning gateway. See [`LightningModule`] for a high level
//! overview.
//!
//! ## Attention: only one operation per contract and round
//! If this module is active the consensus' conflict filter must ensure that at most one operation
//! (spend, funding) happens per contract per round

pub mod config;
pub mod contracts;
mod db;

use crate::config::LightningModuleConfig;
use crate::contracts::incoming::{
    DecryptedPreimage, EncryptedPreimage, IncomingContractOffer, OfferId, PreimageDecryptionShare,
};
use crate::contracts::{
    Contract, ContractId, ContractOutcome, FundedContract, IdentifyableContract,
};
use crate::db::{
    AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractKeyPrefix,
    ContractUpdateKey, OfferKey, OfferKeyPrefix, ProposeDecryptionShareKey,
    ProposeDecryptionShareKeyPrefix,
};
use async_trait::async_trait;
use bitcoin_hashes::Hash as BitcoinHash;
use dashmap::DashMap;
use itertools::Itertools;

use minimint_api::db::batch::{BatchItem, BatchTx};
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::audit::Audit;
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::{api_endpoint, ApiEndpoint, ApiError};
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::Sub;
use tokio::sync::Notify;

use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info_span, instrument, trace, warn};

/// The lightning module implements an account system. It does not have the privacy guarantees of
/// the e-cash mint module but instead allows for smart contracting. There exist three contract
/// types that can be used to "lock" accounts:
///
///   * [Account]: an account locked with a schnorr public key
///   * [Outgoing]: an account locked with an HTLC-like contract allowing to incentivize an external
///     Lightning node to make payments for the funder
///   * [Incoming]: a contract type that represents the acquisition of a preimage belonging to a hash.
///     Every incoming contract is preceded by an offer that specifies how much the seller is asking
///     for the preimage to a particular hash. It also contains some threshold-encrypted data. Once
///     the contract is funded the data is decrypted. If it is a valid preimage the contract's funds
///     are now accessible to the creator of the offer, if not they are accessible to the funder.
///
/// These three primitives allow to integrate the federation with the wider Lightning network
/// through a centralized but untrusted (except for availability) Lightning gateway server.
///
/// [Account]: contracts::account::AccountContract
/// [Outgoing]: contracts::outgoing::OutgoingContract
/// [Incoming]: contracts::incoming::IncomingContract
pub struct LightningModule {
    cfg: LightningModuleConfig,
    db: Arc<dyn Database>,
    offers: DashMap<bitcoin_hashes::sha256::Hash, Arc<Notify>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractInput {
    pub contract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other witness data than a
    /// signature. The signature is aggregated on the transaction level, so only the optional
    /// preimage remains.
    pub witness: Option<contracts::outgoing::Preimage>,
}

/// Represents an output of the Lightning module.
///
/// There are two sub-types:
///   * Normal contracts users may lock funds in
///   * Offers to buy preimages (see `contracts::incoming` docs)
///
/// The offer type exists to register `IncomingContractOffer`s. Instead of patching in a second way
/// of letting clients submit consensus items outside of transactions we let offers be a 0-amount
/// output. We need to take care to allow 0-input, 1-output transactions for that to allow users
/// to receive their fist tokens via LN without already having tokens.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum ContractOrOfferOutput {
    Contract(ContractOutput),
    Offer(contracts::incoming::IncomingContractOffer),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub amount: minimint_api::Amount,
    pub contract: contracts::Contract,
}

#[derive(Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct ContractAccount {
    pub amount: minimint_api::Amount,
    pub contract: contracts::FundedContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum OutputOutcome {
    Contract {
        id: ContractId,
        outcome: ContractOutcome,
    },
    Offer {
        id: OfferId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct DecryptionShareCI {
    pub contract_id: ContractId,
    pub share: PreimageDecryptionShare,
}

#[async_trait(?Send)]
impl FederationModule for LightningModule {
    type Error = LightningModuleError;
    type TxInput = ContractInput;
    type TxOutput = ContractOrOfferOutput;
    type TxOutputOutcome = OutputOutcome;
    type ConsensusItem = DecryptionShareCI;
    type VerificationCache = ();

    async fn await_consensus_proposal<'a>(&'a self, rng: impl RngCore + CryptoRng + 'a) {
        if self.consensus_proposal(rng).await.is_empty() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        self.db
            .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
            .map(|res| {
                let (ProposeDecryptionShareKey(contract_id), share) = res.expect("DB error");
                DecryptionShareCI { contract_id, share }
            })
            .collect()
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        batch.append_from_iter(consensus_items.into_iter().map(|(peer, decryption_share)| {
            let span = info_span!("process decryption share", %peer);
            let _guard = span.enter();

            BatchItem::insert_new(
                AgreedDecryptionShareKey(decryption_share.contract_id, peer),
                decryption_share.share,
            )
        }));
        batch.commit();
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::TxInput>,
    ) -> Self::VerificationCache {
    }

    fn validate_input<'a>(
        &self,
        interconnect: &dyn ModuleInterconect,
        _cache: &Self::VerificationCache,
        input: &'a Self::TxInput,
    ) -> Result<InputMeta<'a>, Self::Error> {
        let account: ContractAccount = self
            .get_contract_account(input.contract_id)
            .ok_or(LightningModuleError::UnknownContract(input.contract_id))?;

        if account.amount < input.amount {
            return Err(LightningModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        let pub_key = match account.contract {
            FundedContract::Outgoing(outgoing) => {
                if outgoing.timelock > block_height(interconnect) {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningModuleError::MissingPreimage)?
                            .0[..],
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningModuleError::InvalidPreimage);
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Account(acc_contract) => acc_contract.key,
            FundedContract::Incoming(incoming) => match incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningModuleError::ContractNotReady);
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => preimage.0,
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        Ok(InputMeta {
            amount: input.amount,
            puk_keys: Box::new(std::iter::once(pub_key)),
        })
    }

    fn apply_input<'a, 'b>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        mut batch: BatchTx<'a>,
        input: &'b Self::TxInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta<'b>, Self::Error> {
        let meta = self.validate_input(interconnect, cache, input)?;

        let account_db_key = ContractKey(input.contract_id);
        let mut contract_account = self
            .db
            .get_value(&account_db_key)
            .expect("DB error")
            .expect("Should fail validation if contract account doesn't exist");
        contract_account.amount -= meta.amount;
        batch.append_insert(account_db_key, contract_account);

        batch.commit();
        Ok(meta)
    }

    fn validate_output(&self, output: &Self::TxOutput) -> Result<Amount, Self::Error> {
        match output {
            ContractOrOfferOutput::Contract(contract) => {
                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = self
                        .db
                        .get_value(&OfferKey(incoming.hash))
                        .expect("DB error")
                        .ok_or(LightningModuleError::NoOffer(incoming.hash))?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningModuleError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ));
                    }
                }

                if contract.amount == Amount::ZERO {
                    Err(LightningModuleError::ZeroOutput)
                } else {
                    Ok(contract.amount)
                }
            }
            ContractOrOfferOutput::Offer(offer) => {
                if !offer.encrypted_preimage.0.verify() {
                    Err(LightningModuleError::InvalidEncryptedPreimage)
                } else {
                    Ok(Amount::ZERO)
                }
            }
        }
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        let amount = self.validate_output(output)?;

        match output {
            ContractOrOfferOutput::Contract(contract) => {
                let contract_db_key = ContractKey(contract.contract.contract_id());
                let updated_contract_account = self
                    .db
                    .get_value(&contract_db_key)
                    .expect("DB error")
                    .map(|mut value: ContractAccount| {
                        value.amount += amount;
                        value
                    })
                    .unwrap_or_else(|| ContractAccount {
                        amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    });
                batch.append_insert(contract_db_key, updated_contract_account);

                batch.append_insert_new(
                    ContractUpdateKey(out_point),
                    OutputOutcome::Contract {
                        id: contract.contract.contract_id(),
                        outcome: contract.contract.to_outcome(),
                    },
                );

                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = self
                        .db
                        .get_value(&OfferKey(incoming.hash))
                        .expect("DB error")
                        .expect("offer exists if output is valid");

                    let decryption_share = self
                        .cfg
                        .threshold_sec_key
                        .decrypt_share(&incoming.encrypted_preimage.0)
                        .expect("We checked for decryption share validity on contract creation");
                    batch.append_insert_new(
                        ProposeDecryptionShareKey(contract.contract.contract_id()),
                        PreimageDecryptionShare(decryption_share),
                    );
                    batch.append_delete(OfferKey(offer.hash));
                }
            }
            ContractOrOfferOutput::Offer(offer) => {
                batch.append_insert_new(
                    ContractUpdateKey(out_point),
                    OutputOutcome::Offer { id: offer.id() },
                );
                // TODO: sanity-check encrypted preimage size
                batch.append_insert_new(OfferKey(offer.hash), (*offer).clone());
            }
        }

        batch.commit();
        Ok(amount)
    }

    #[instrument(skip_all)]
    async fn end_consensus_epoch<'a>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // Decrypt preimages
        let preimage_decryption_shares = self
            .db
            .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
            .map(|res| {
                let (key, value) = res.expect("DB error");
                (key.0, (key.1, value))
            })
            .into_group_map();

        let mut bad_peers = vec![];
        for (contract_id, shares) in preimage_decryption_shares {
            let peers: Vec<PeerId> = shares.iter().map(|(peer, _)| *peer).collect();
            let span = info_span!("decrypt_preimage", %contract_id);
            let _gaurd = span.enter();

            let incoming_contract = match self.get_contract_account(contract_id) {
                Some(ContractAccount {
                    contract: FundedContract::Incoming(incoming),
                    ..
                }) => incoming.contract,
                _ => {
                    warn!("Received decryption share for non-existent incoming contract");
                    for peer in peers {
                        batch.append_delete(AgreedDecryptionShareKey(contract_id, peer));
                    }
                    continue;
                }
            };

            let valid_shares: HashMap<PeerId, PreimageDecryptionShare> = shares
                .into_iter()
                .filter(|(peer, share)| {
                    self.validate_decryption_share(
                        *peer,
                        share,
                        &incoming_contract.encrypted_preimage,
                    )
                })
                .collect();

            for peer in consensus_peers.sub(&valid_shares.keys().cloned().collect()) {
                bad_peers.push(peer);
                warn!("{} did not contribute valid decryption shares", peer);
            }

            if valid_shares.len() < self.cfg.threshold {
                warn!(
                    valid_shares = %valid_shares.len(),
                    shares_needed = %self.cfg.threshold,
                    "Too few decryption shares"
                );
                continue;
            }
            debug!("Beginning to decrypt preimage");

            let contract = self
                .get_contract_account(contract_id)
                .expect("decryption shares without contracts should be discarded earlier"); // FIXME: verify

            let (incoming_contract, out_point) = match contract.contract {
                FundedContract::Incoming(incoming) => (incoming.contract, incoming.out_point),
                _ => panic!(
                    "decryption shares without incoming contracts should be discarded earlier"
                ),
            };

            if !matches!(
                incoming_contract.decrypted_preimage,
                DecryptedPreimage::Pending
            ) {
                warn!("Tried to decrypt the same preimage twice, this should not happen.");
                continue;
            }

            let preimage = match self.cfg.threshold_pub_keys.decrypt(
                valid_shares
                    .iter()
                    .map(|(peer, share)| (peer.to_usize(), &share.0)),
                &incoming_contract.encrypted_preimage.0,
            ) {
                Ok(preimage) => preimage,
                Err(_) => {
                    // TODO: check if that can happen even though shares are verified before
                    error!(contract_hash = %incoming_contract.hash, "Failed to decrypt preimage");
                    continue;
                }
            };

            // Delete decryption shares once we've decrypted the preimage
            batch.append_delete(ProposeDecryptionShareKey(contract_id));
            for peer in peers {
                batch.append_delete(AgreedDecryptionShareKey(contract_id, peer));
            }

            let decrypted_preimage = if preimage.len() != 32 {
                DecryptedPreimage::Invalid
            } else if incoming_contract.hash == bitcoin_hashes::sha256::Hash::hash(&preimage) {
                if let Ok(preimage_key) = secp256k1::XOnlyPublicKey::from_slice(&preimage) {
                    DecryptedPreimage::Some(crate::contracts::incoming::Preimage(preimage_key))
                } else {
                    DecryptedPreimage::Invalid
                }
            } else {
                DecryptedPreimage::Invalid
            };
            debug!(?decrypted_preimage);

            // TODO: maybe define update helper fn
            // Update contract
            let contract_db_key = ContractKey(contract_id);
            let mut contract_account = self
                .db
                .get_value(&contract_db_key)
                .expect("DB error")
                .expect("checked before that it exists");
            let mut incoming = match &mut contract_account.contract {
                FundedContract::Incoming(incoming) => incoming,
                _ => unreachable!("previously checked that it's an incoming contrac"),
            };
            incoming.contract.decrypted_preimage = decrypted_preimage.clone();
            trace!(?contract_account, "Updating contract account");
            batch.append_insert(contract_db_key, contract_account);

            // Update output outcome
            let outcome_db_key = ContractUpdateKey(out_point);
            let mut outcome = self
                .db
                .get_value(&outcome_db_key)
                .expect("DB error")
                .expect("outcome was created on funding");
            let incoming_contract_outcome_preimage = match &mut outcome {
                OutputOutcome::Contract {
                    outcome: ContractOutcome::Incoming(decryption_outcome),
                    ..
                } => decryption_outcome,
                _ => panic!("We are expeccting an incoming contract"),
            };
            *incoming_contract_outcome_preimage = decrypted_preimage.clone();
            batch.append_insert(outcome_db_key, outcome);
        }
        batch.commit();

        bad_peers
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        self.db
            .get_value(&ContractUpdateKey(out_point))
            .expect("DB error")
    }

    fn audit(&self, audit: &mut Audit) {
        audit.add_items(&self.db, &ContractKeyPrefix, |_, v| {
            -(v.amount.milli_sat as i64)
        });
    }

    fn api_base_name(&self) -> &'static str {
        "ln"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        const ENDPOINTS: &[ApiEndpoint<LightningModule>] = &[
            api_endpoint! {
                "/account",
                async |module: &LightningModule, contract_id: ContractId| -> ContractAccount {
                    module
                        .get_contract_account(contract_id)
                        .ok_or_else(|| ApiError::not_found(String::from("Contract not found")))
                }
            },
            api_endpoint! {
                "/offers",
                async |module: &LightningModule, _params: ()| -> Vec<IncomingContractOffer> {
                    Ok(module.get_offers())
                }
            },
            api_endpoint! {
                "/offer",
                async |module: &LightningModule, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    // # Concurrency
                    //
                    // - first concurrent request adds new notify into map (it will not be present).
                    // - if the offer is in the database.
                    //      - first concurrent request notifies all others.
                    //      - all other requests wait for notication.
                    // - otherwise wait for notification.

                    use dashmap::mapref::entry::Entry;
                    match module.offers.entry(payment_hash.clone()) {
                        // first concurrent request
                        Entry::Vacant(v) => {
                            let notify = Arc::new(Notify::new());
                            // TODO: add timeout to prevent memory leak
                            v.insert(Arc::clone(&notify));
                            // start waiting before droping the entry lock
                            let n = (*notify).notified();
                            drop(v); // unlock the dashmap entry
                            if let Some(offer) = module.get_offer(payment_hash) {
                                // already in db
                                module.offers.remove(&payment_hash);
                                // remove before notify to make sure none to wait just *after*
                                // we notify and before we remove from map
                                (*notify).notify_waiters();
                                return Ok(offer);
                            }

                            n.await;
                            // the notifier is reponsible for removing entry from map
                        }
                        // other concurrent requests
                        Entry::Occupied(o) => {
                            let notify = o.get().clone();
                            // start waiting before droping the entry lock
                            let n = notify.notified();
                            drop(o); // unlock the dashmap entry
                            n.await;
                        },
                    }
                    let offer = module
                        .get_offer(payment_hash)
                        .ok_or_else(|| ApiError::not_found(String::from("Offer not found")))?;

                    Ok(offer)
            } },
        ];
        ENDPOINTS
    }
}

impl LightningModule {
    pub fn new(cfg: LightningModuleConfig, db: Arc<dyn Database>) -> LightningModule {
        LightningModule {
            cfg,
            db,
            offers: DashMap::new(),
        }
    }

    fn validate_decryption_share(
        &self,
        peer: PeerId,
        share: &PreimageDecryptionShare,
        message: &EncryptedPreimage,
    ) -> bool {
        self.cfg
            .threshold_pub_keys
            .public_key_share(peer.to_usize())
            .verify_decryption_share(&share.0, &message.0)
    }

    pub fn get_offer(
        &self,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        self.db
            .get_value(&OfferKey(payment_hash))
            .expect("DB error")
    }

    pub fn get_offers(&self) -> Vec<IncomingContractOffer> {
        self.db
            .find_by_prefix(&OfferKeyPrefix)
            .map(|res| res.expect("DB error").1)
            .collect()
    }

    pub fn get_contract_account(&self, contract_id: ContractId) -> Option<ContractAccount> {
        self.db
            .get_value(&ContractKey(contract_id))
            .expect("DB error")
    }
}

fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But for internal
    // calls the data is available instantly in one go, so we can just block on it.
    let body = futures::executor::block_on(interconnect.call(
        "wallet",
        "/block_height".to_owned(),
        Default::default(),
    ))
    .expect("Wallet module not present or malfunctioning!");

    serde_json::from_value(body).expect("Malformed block height response from wallet module!")
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LightningModuleError {
    #[error("The the input contract {0} does not exist")]
    UnknownContract(ContractId),
    #[error("The input contract has too little funds, got {0}, input spends {1}")]
    InsufficientFunds(Amount, Amount),
    #[error("An outgoing LN contract spend did not provide a preimage")]
    MissingPreimage,
    #[error("An outgoing LN contract spend provided a wrong preimage")]
    InvalidPreimage,
    #[error("Incoming contract not ready to be spent yet, decryption in progress")]
    ContractNotReady,
    #[error("Output contract value may not be zero unless it's an offer output")]
    ZeroOutput,
    #[error("Offer contains invalid threshold-encrypted data")]
    InvalidEncryptedPreimage,
    #[error(
        "The incoming LN account requires more funding according to the offer (need {0} got {1})"
    )]
    InsufficientIncomingFunding(Amount, Amount),
    #[error("No offer found for payment hash {0}")]
    NoOffer(secp256k1::hashes::sha256::Hash),
}
