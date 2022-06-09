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
    AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractUpdateKey,
    OfferKey, OfferKeyPrefix, ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
};
use async_trait::async_trait;
use bitcoin_hashes::Hash as BitcoinHash;
use contracts::account::{self, AccountContract};
use itertools::Itertools;
use minimint_api::db::batch::{BatchItem, BatchTx};
use minimint_api::db::Database;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::module::interconnect::ModuleInterconect;
use minimint_api::module::{http, ApiEndpoint};
use minimint_api::{Amount, FederationModule, PeerId};
use minimint_api::{InputMeta, OutPoint};
use secp256k1::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractInput {
    pub crontract_id: contracts::ContractId,
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
// #[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
// pub enum ContractOrOfferOutput {
//     Contract(ContractOutput),
//     Offer(contracts::incoming::IncomingContractOffer),
// }

// #[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
// pub struct ContractOutput {
//     pub amount: minimint_api::Amount,
//     pub contract: account::AccountContract,
// }

// #[derive(Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize)]
// pub struct ContractAccount {
//     pub amount: minimint_api::Amount,
//     pub contract: contracts::FundedContract,
// }

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
    type TxOutput = AccountContract;
    type TxOutputOutcome = ContractId;
    type ConsensusItem = ();
    type VerificationCache = ();

    async fn consensus_proposal<'a>(
        &'a self,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<Self::ConsensusItem> {
        // self.db
        //     .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
        //     .map(|res| {
        //         let (ProposeDecryptionShareKey(contract_id), share) = res.expect("DB error");
        //         DecryptionShareCI { contract_id, share }
        //     })
        //     .collect()
        vec![]
    }

    async fn begin_consensus_epoch<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) {
        // batch.append_from_iter(consensus_items.into_iter().filter_map(
        //     |(peer, decryption_share)| {
        //         let span = info_span!("process decryption share", %peer);
        //         let _guard = span.enter();
        //         let contract: ContractAccount = self
        //             .get_contract_account(decryption_share.contract_id)
        //             .or_else(|| {
        //                 warn!("Received decryption share fot non-incoming contract");
        //                 None
        //             })?;
        //         let incoming_contract = match contract.contract {
        //             FundedContract::Incoming(incoming) => incoming.contract,
        //             _ => {
        //                 warn!("Received decryption share fot non-incoming contract");
        //                 return None;
        //             }
        //         };

        //         if !self.validate_decryption_share(
        //             peer,
        //             &decryption_share.share,
        //             &incoming_contract.encrypted_preimage,
        //         ) {
        //             warn!("Received invalid decryption share");
        //             return None;
        //         }

        //         Some(BatchItem::insert_new(
        //             AgreedDecryptionShareKey(decryption_share.contract_id, peer),
        //             decryption_share.share,
        //         ))
        //     },
        // ));
        // batch.commit();
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
        let account: account::AccountContract = self
            .get_contract_account(input.crontract_id)
            .ok_or(LightningModuleError::UnknownContract(input.crontract_id))?;

        if account.amount < input.amount {
            return Err(LightningModuleError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        // let pub_key = match account.contract {
        //     FundedContract::Outgoing(outgoing) => {
        //         if outgoing.timelock > block_height(interconnect) {
        //             // If the timelock hasn't expired yet …
        //             let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
        //                 &input
        //                     .witness
        //                     .as_ref()
        //                     .ok_or(LightningModuleError::MissingPreimage)?
        //                     .0[..],
        //             );

        //             // … and the spender provides a valid preimage …
        //             if preimage_hash != outgoing.hash {
        //                 return Err(LightningModuleError::InvalidPreimage);
        //             }

        //             // … then the contract account can be spent using the gateway key,
        //             outgoing.gateway_key
        //         } else {
        //             // otherwise the user can claim the funds back.
        //             outgoing.user_key
        //         }
        //     }
        //     FundedContract::Account(acc_contract) => acc_contract.key,
        //     FundedContract::Incoming(incoming) => match incoming.contract.decrypted_preimage {
        //         // Once the preimage has been decrypted …
        //         DecryptedPreimage::Pending => {
        //             return Err(LightningModuleError::ContractNotReady);
        //         }
        //         // … either the user may spend the funds since they sold a valid preimage …
        //         DecryptedPreimage::Some(preimage) => preimage.0,
        //         // … or the gateway may claim back funds for not receiving the advertised preimage.
        //         DecryptedPreimage::Invalid => incoming.contract.gateway_key,
        //     },
        // };
        let pub_key = account.key;

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

        let account_db_key = ContractKey(input.crontract_id);
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
        let contract = output;
        if contract.amount == Amount::ZERO {
            Err(LightningModuleError::ZeroOutput)
        } else {
            Ok(contract.amount)
        }
    }

    fn apply_output<'a>(
        &'a self,
        mut batch: BatchTx<'a>,
        output: &'a Self::TxOutput,
        out_point: OutPoint,
    ) -> Result<Amount, Self::Error> {
        let amount = self.validate_output(output)?;
        let contract = output;

        // Set a balance on this account
        let contract_db_key = ContractKey(contract.contract_id());
        let updated_contract_account = self
            .db
            .get_value(&contract_db_key)
            .expect("DB error")
            .map(|mut value: account::AccountContract| {
                value.amount += amount;
                value
            })
            .unwrap_or_else(|| account::AccountContract {
                amount,
                key: contract.key.clone(),
            });
        batch.append_insert(contract_db_key, updated_contract_account);

        batch.commit();
        Ok(amount)
    }

    #[instrument(skip_all)]
    async fn end_consensus_epoch<'a>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        mut batch: BatchTx<'a>,
        _rng: impl RngCore + CryptoRng + 'a,
    ) -> Vec<PeerId> {
        // FIXME: use this to drop peers with conflicting simplicity contract IDs
        vec![]
    }

    fn output_status(&self, out_point: OutPoint) -> Option<Self::TxOutputOutcome> {
        todo!()

        // FIXME: save ContractUpdateKey to db in `apply_output` so that we can look up contracts by outpoint
        // as required by this method

        // self.db
        //     .get_value(&ContractUpdateKey(out_point))
        //     .expect("DB error")
    }

    fn api_base_name(&self) -> &'static str {
        "ln"
    }

    fn api_endpoints(&self) -> &'static [ApiEndpoint<Self>] {
        &[
            ApiEndpoint {
                path_spec: "/account/:contract_id",
                params: &["contract_id"],
                method: http::Method::Get,
                handler: |module, params, _body| {
                    let contract_id: ContractId = match params
                        .get("contract_id")
                        .expect("Contract id not supplied")
                        .parse()
                    {
                        Ok(id) => id,
                        Err(_) => return Ok(http::Response::new(400)),
                    };

                    let contract_account = module
                        .get_contract_account(contract_id)
                        .ok_or_else(|| http::Error::from_str(404, "Not found"))?;

                    debug!(%contract_id, "Sending contract account info");
                    let body = http::Body::from_json(&contract_account).expect("encoding error");
                    Ok(body.into())
                },
            },
            ApiEndpoint {
                path_spec: "/offers",
                params: &[],
                method: http::Method::Get,
                handler: |module, _params, _body| {
                    let offers = module.get_offers();
                    let body = http::Body::from_json(&offers).expect("encoding error");
                    Ok(body.into())
                },
            },
        ]
    }
}

impl LightningModule {
    pub fn new(cfg: LightningModuleConfig, db: Arc<dyn Database>) -> LightningModule {
        LightningModule { cfg, db }
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

    pub fn get_offers(&self) -> Vec<IncomingContractOffer> {
        self.db
            .find_by_prefix(&OfferKeyPrefix)
            .map(|res| res.expect("DB error").1)
            .collect()
    }

    pub fn get_contract_account(
        &self,
        contract_id: ContractId,
    ) -> Option<account::AccountContract> {
        self.db
            .get_value(&ContractKey(contract_id))
            .expect("DB error")
    }
}

fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But for internal
    // calls the data is available instantly in one go, so we can just block on it.
    futures::executor::block_on(
        interconnect
            .call(
                "wallet",
                "/block_height".to_owned(),
                http::Method::Get,
                Default::default(),
            )
            .expect("Wallet module not present or malfunctioning!")
            .body_json(),
    )
    .expect("Malformed block height response from wallet module!")
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
