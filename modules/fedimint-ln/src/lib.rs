//! # Lightning Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway. See
//! [`Lightning`] for a high level overview.
//!
//! ## Attention: only one operation per contract and round
//! If this module is active the consensus' conflict filter must ensure that at
//! most one operation (spend, funding) happens per contract per round

extern crate core;

pub mod config;
pub mod contracts;
pub mod db;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::ops::Sub;

use bitcoin_hashes::Hash as BitcoinHash;
use config::FeeConsensus;
use db::{DbKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix};
use fedimint_core::config::{
    ConfigGenParams, DkgResult, ModuleConfigResponse, ServerModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::{
    Decoder, ModuleInstanceId, ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::interconnect::ModuleInterconect;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, ConsensusProposal, CoreConsensusVersion,
    InputMeta, IntoModuleError, ModuleCommon, ModuleConsensusVersion, ModuleError, ModuleGen,
    PeerHandle, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::time::SystemTime;
use fedimint_core::{
    apply, async_trait_maybe_send, plugin_types_trait_impl, push_db_pair_items, Amount, NumPeers,
    OutPoint, PeerId, ServerModule,
};
#[cfg(feature = "server")]
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use itertools::Itertools;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use thiserror::Error;
use tracing::{debug, error, info_span, instrument, trace, warn};
use url::Url;

use crate::config::{
    LightningClientConfig, LightningConfig, LightningConfigConsensus, LightningConfigPrivate,
};
use crate::contracts::incoming::{IncomingContractOffer, OfferId};
use crate::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, EncryptedPreimage, FundedContract,
    IdentifyableContract, Preimage, PreimageDecryptionShare,
};
use crate::db::{
    AgreedDecryptionShareKey, AgreedDecryptionShareKeyPrefix, ContractKey, ContractKeyPrefix,
    ContractUpdateKey, ContractUpdateKeyPrefix, OfferKey, OfferKeyPrefix,
    ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
};

const KIND: ModuleKind = ModuleKind::from_static_str("ln");

/// The lightning module implements an account system. It does not have the
/// privacy guarantees of the e-cash mint module but instead allows for smart
/// contracting. There exist three contract types that can be used to "lock"
/// accounts:
///
///   * [Outgoing]: an account locked with an HTLC-like contract allowing to
///     incentivize an external Lightning node to make payments for the funder
///   * [Incoming]: a contract type that represents the acquisition of a
///     preimage belonging to a hash. Every incoming contract is preceded by an
///     offer that specifies how much the seller is asking for the preimage to a
///     particular hash. It also contains some threshold-encrypted data. Once
///     the contract is funded the data is decrypted. If it is a valid preimage
///     the contract's funds are now accessible to the creator of the offer, if
///     not they are accessible to the funder.
///
/// These three primitives allow to integrate the federation with the wider
/// Lightning network through a centralized but untrusted (except for
/// availability) Lightning gateway server.
///
/// [Outgoing]: contracts::outgoing::OutgoingContract
/// [Incoming]: contracts::incoming::IncomingContract
#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct LightningInput {
    pub contract_id: contracts::ContractId,
    /// While for now we only support spending the entire contract we need to
    /// avoid
    pub amount: Amount,
    /// Of the three contract types only the outgoing one needs any other
    /// witness data than a signature. The signature is aggregated on the
    /// transaction level, so only the optional preimage remains.
    pub witness: Option<Preimage>,
}

impl std::fmt::Display for LightningInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Lightning Contract {} with amount {}",
            self.contract_id, self.amount
        )
    }
}

/// Represents an output of the Lightning module.
///
/// There are three sub-types:
///   * Normal contracts users may lock funds in
///   * Offers to buy preimages (see `contracts::incoming` docs)
///   * Early cancellation of outgoing contracts before their timeout
///
/// The offer type exists to register `IncomingContractOffer`s. Instead of
/// patching in a second way of letting clients submit consensus items outside
/// of transactions we let offers be a 0-amount output. We need to take care to
/// allow 0-input, 1-output transactions for that to allow users to receive
/// their fist notes via LN without already having notes.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutput {
    /// Fund contract
    Contract(ContractOutput),
    /// Create incoming contract offer
    Offer(contracts::incoming::IncomingContractOffer),
    /// Allow early refund of outgoing contract
    CancelOutgoing {
        /// Contract to update
        contract: ContractId,
        /// Signature of gateway
        gateway_signature: secp256k1::schnorr::Signature,
    },
}

impl std::fmt::Display for LightningOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutput::Contract(ContractOutput { amount, contract }) => match contract {
                Contract::Incoming(incoming) => {
                    write!(
                        f,
                        "LN Incoming Contract for {} hash {}",
                        amount, incoming.hash
                    )
                }
                Contract::Outgoing(outgoing) => {
                    write!(
                        f,
                        "LN Outgoing Contract for {} hash {}",
                        amount, outgoing.hash
                    )
                }
            },
            LightningOutput::Offer(offer) => {
                write!(f, "LN offer for {} with hash {}", offer.amount, offer.hash)
            }
            LightningOutput::CancelOutgoing { contract, .. } => {
                write!(f, "LN outgoing contract cancellation {contract}")
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub amount: fedimint_core::Amount,
    pub contract: contracts::Contract,
}

#[derive(Debug, Eq, PartialEq, Hash, Encodable, Decodable, Serialize, Deserialize, Clone)]
pub struct ContractAccount {
    pub amount: fedimint_core::Amount,
    pub contract: contracts::FundedContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum LightningOutputOutcome {
    Contract {
        id: ContractId,
        outcome: ContractOutcome,
    },
    Offer {
        id: OfferId,
    },
}

impl LightningOutputOutcome {
    pub fn is_permanent(&self) -> bool {
        match self {
            LightningOutputOutcome::Contract { id: _, outcome } => outcome.is_permanent(),
            LightningOutputOutcome::Offer { .. } => true,
        }
    }
}

impl std::fmt::Display for LightningOutputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightningOutputOutcome::Contract { id, .. } => {
                write!(f, "LN Contract {id}")
            }
            LightningOutputOutcome::Offer { id } => {
                write!(f, "LN Offer {id}")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable, PartialEq, Eq, Hash)]
pub struct LightningGateway {
    /// Channel identifier assigned to the mint by the gateway.
    /// All clients in this federation should use this value as
    /// `short_channel_id` when creating invoices to be settled by this
    /// gateway.
    pub mint_channel_id: u64,
    pub mint_pub_key: secp256k1::XOnlyPublicKey,
    pub node_pub_key: secp256k1::PublicKey,
    pub api: Url,
    /// Route hints to reach the LN node of the gateway.
    ///
    /// These will be appended with the route hint of the recipient's virtual
    /// channel. To keeps invoices small these should be used sparingly.
    pub route_hints: Vec<route_hints::RouteHint>,
    /// Limits the validity of the announcement to allow updates
    pub valid_until: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct LightningConsensusItem {
    pub contract_id: ContractId,
    pub share: PreimageDecryptionShare,
}

impl std::fmt::Display for LightningConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LN Decryption Share for contract {}", self.contract_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Encodable, Decodable, Serialize, Deserialize)]
pub struct LightningVerificationCache;

#[derive(Debug)]
pub struct LightningGen;

#[apply(async_trait_maybe_send!)]
impl ModuleGen for LightningGen {
    const KIND: ModuleKind = KIND;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    fn decoder(&self) -> Decoder {
        <Lightning as ServerModule>::decoder()
    }

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[ModuleConsensusVersion(0)]
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _env: &BTreeMap<OsString, OsString>,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<DynServerModule> {
        Ok(Lightning::new(cfg.to_typed()?).into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let sks = threshold_crypto::SecretKeySet::random(peers.degree(), &mut OsRng);
        let pks = sks.public_keys();

        let server_cfg = peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningConfig {
                        consensus: LightningConfigConsensus {
                            threshold_pub_keys: pks.clone(),
                            fee_consensus: FeeConsensus::default(),
                        },
                        private: LightningConfigPrivate {
                            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        },
                    }
                    .to_erased(),
                )
            })
            .collect();

        server_cfg
    }

    // FIXME: Currently required because the client depends on the server modules
    #[cfg(not(feature = "server"))]
    async fn distributed_gen(
        &self,
        _peers: &PeerHandle,
        _params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        unimplemented!()
    }

    #[cfg(feature = "server")]
    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        _params: &ConfigGenParams,
    ) -> DkgResult<ServerModuleConfig> {
        let g1 = peers.run_dkg_g1(()).await?;

        let keys = g1[&()].threshold_crypto();

        let server = LightningConfig {
            consensus: LightningConfigConsensus {
                threshold_pub_keys: keys.public_key_set,
                fee_consensus: Default::default(),
            },
            private: LightningConfigPrivate {
                threshold_sec_key: keys.secret_key_share,
            },
        };

        Ok(server.to_erased())
    }

    fn to_config_response(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ModuleConfigResponse> {
        let config = serde_json::from_value::<LightningConfigConsensus>(config)?;

        Ok(ModuleConfigResponse {
            client: config.to_client_config(),
            consensus_hash: config.consensus_hash()?,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config
            .to_typed::<LightningConfig>()?
            .validate_config(identity)
    }

    fn hash_client_module(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<bitcoin_hashes::sha256::Hash> {
        serde_json::from_value::<LightningClientConfig>(config)?.consensus_hash()
    }

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut lightning: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> =
            BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::AgreedDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        AgreedDecryptionShareKeyPrefix,
                        AgreedDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Accepted Decryption Shares"
                    );
                }
                DbKeyPrefix::Contract => {
                    push_db_pair_items!(
                        dbtx,
                        ContractKeyPrefix,
                        ContractKey,
                        ContractAccount,
                        lightning,
                        "Contracts"
                    );
                }
                DbKeyPrefix::ContractUpdate => {
                    push_db_pair_items!(
                        dbtx,
                        ContractUpdateKeyPrefix,
                        ContractUpdateKey,
                        LightningOutputOutcome,
                        lightning,
                        "Contract Updates"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGateway,
                        lightning,
                        "Lightning Gateways"
                    );
                }
                DbKeyPrefix::Offer => {
                    push_db_pair_items!(
                        dbtx,
                        OfferKeyPrefix,
                        OfferKey,
                        IncomingContractOffer,
                        lightning,
                        "Offers"
                    );
                }
                DbKeyPrefix::ProposeDecryptionShare => {
                    push_db_pair_items!(
                        dbtx,
                        ProposeDecryptionShareKeyPrefix,
                        ProposeDecryptionShareKey,
                        PreimageDecryptionShare,
                        lightning,
                        "Proposed Decryption Shares"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}

pub struct LightningModuleTypes;

impl ModuleCommon for LightningModuleTypes {
    type Input = LightningInput;
    type Output = LightningOutput;
    type OutputOutcome = LightningOutputOutcome;
    type ConsensusItem = LightningConsensusItem;
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Gen = LightningGen;
    type VerificationCache = LightningVerificationCache;

    fn versions(&self) -> (ModuleConsensusVersion, &[ApiVersion]) {
        (
            ModuleConsensusVersion(0),
            &[ApiVersion { major: 0, minor: 0 }],
        )
    }

    async fn await_consensus_proposal(&self, dbtx: &mut DatabaseTransaction<'_>) {
        if !self.consensus_proposal(dbtx).await.forces_new_epoch() {
            std::future::pending().await
        }
    }

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ConsensusProposal<LightningConsensusItem> {
        ConsensusProposal::new_auto_trigger(
            dbtx.find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                .await
                .map(|res| {
                    let (ProposeDecryptionShareKey(contract_id), share) = res.expect("DB error");
                    LightningConsensusItem { contract_id, share }
                })
                .collect::<Vec<LightningConsensusItem>>()
                .await,
        )
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_items: Vec<(PeerId, LightningConsensusItem)>,
    ) {
        for (peer, decryption_share) in consensus_items.into_iter() {
            let span = info_span!("process decryption share", %peer);
            let _guard = span.enter();

            dbtx.insert_new_entry(
                &AgreedDecryptionShareKey(decryption_share.contract_id, peer),
                &decryption_share.share,
            )
            .await
            .expect("DB Error");
        }
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a LightningInput>,
    ) -> Self::VerificationCache {
        LightningVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        interconnect: &dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        input: &'a LightningInput,
    ) -> Result<InputMeta, ModuleError> {
        let account: ContractAccount = self
            .get_contract_account(dbtx, input.contract_id)
            .await
            .ok_or(LightningError::UnknownContract(input.contract_id))
            .into_module_error_other()?;

        if account.amount < input.amount {
            return Err(LightningError::InsufficientFunds(
                account.amount,
                input.amount,
            ))
            .into_module_error_other();
        }

        let pub_key = match account.contract {
            FundedContract::Outgoing(outgoing) => {
                if outgoing.timelock > block_height(interconnect).await && !outgoing.cancelled {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningError::MissingPreimage)
                            .into_module_error_other()?
                            .0,
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningError::InvalidPreimage).into_module_error_other();
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Incoming(incoming) => match incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningError::ContractNotReady).into_module_error_other();
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => match preimage.to_public_key() {
                    Ok(pub_key) => pub_key,
                    Err(_) => {
                        return Err(LightningError::InvalidPreimage).into_module_error_other()
                    }
                },
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: input.amount,
                fee: self.cfg.consensus.fee_consensus.contract_input,
            },
            puk_keys: vec![pub_key],
        })
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        interconnect: &'a dyn ModuleInterconect,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b LightningInput,
        cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        let meta = self
            .validate_input(interconnect, dbtx, cache, input)
            .await?;

        let account_db_key = ContractKey(input.contract_id);
        let mut contract_account = dbtx
            .get_value(&account_db_key)
            .await
            .expect("DB error")
            .expect("Should fail validation if contract account doesn't exist");
        contract_account.amount -= meta.amount.amount;
        dbtx.insert_entry(&account_db_key, &contract_account)
            .await
            .expect("DB Error");

        Ok(meta)
    }

    async fn validate_output(
        &self,
        dbtx: &mut DatabaseTransaction,
        output: &LightningOutput,
    ) -> Result<TransactionItemAmount, ModuleError> {
        match output {
            LightningOutput::Contract(contract) => {
                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .expect("DB error")
                        .ok_or(LightningError::NoOffer(incoming.hash))
                        .into_module_error_other()?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ))
                        .into_module_error_other();
                    }
                }

                if contract.amount == Amount::ZERO {
                    Err(LightningError::ZeroOutput).into_module_error_other()
                } else {
                    Ok(TransactionItemAmount {
                        amount: contract.amount,
                        fee: self.cfg.consensus.fee_consensus.contract_output,
                    })
                }
            }
            LightningOutput::Offer(offer) => {
                if !offer.encrypted_preimage.0.verify() {
                    Err(LightningError::InvalidEncryptedPreimage).into_module_error_other()
                } else {
                    Ok(TransactionItemAmount::ZERO)
                }
            }
            LightningOutput::CancelOutgoing {
                contract,
                gateway_signature,
            } => {
                let contract_account = dbtx
                    .get_value(&ContractKey(*contract))
                    .await
                    .expect("DB error")
                    .ok_or(LightningError::UnknownContract(*contract))
                    .into_module_error_other()?;

                let outgoing_contract = match &contract_account.contract {
                    FundedContract::Outgoing(contract) => contract,
                    _ => {
                        return Err(LightningError::NotOutgoingContract).into_module_error_other();
                    }
                };

                secp256k1::global::SECP256K1
                    .verify_schnorr(
                        gateway_signature,
                        &outgoing_contract.cancellation_message().into(),
                        &outgoing_contract.gateway_key,
                    )
                    .map_err(|_| LightningError::InvalidCancellationSignature)
                    .into_module_error_other()?;

                Ok(TransactionItemAmount::ZERO)
            }
        }
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        let amount = self.validate_output(dbtx, output).await?;

        match output {
            LightningOutput::Contract(contract) => {
                let contract_db_key = ContractKey(contract.contract.contract_id());
                let updated_contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .expect("DB error")
                    .map(|mut value: ContractAccount| {
                        value.amount += amount.amount;
                        value
                    })
                    .unwrap_or_else(|| ContractAccount {
                        amount: amount.amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    });
                dbtx.insert_entry(&contract_db_key, &updated_contract_account)
                    .await
                    .expect("DB Error");

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Contract {
                        id: contract.contract.contract_id(),
                        outcome: contract.contract.to_outcome(),
                    },
                )
                .await
                .expect("DB Error");

                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .expect("DB error")
                        .expect("offer exists if output is valid");

                    let decryption_share = self
                        .cfg
                        .private
                        .threshold_sec_key
                        .decrypt_share(&incoming.encrypted_preimage.0)
                        .expect("We checked for decryption share validity on contract creation");
                    dbtx.insert_new_entry(
                        &ProposeDecryptionShareKey(contract.contract.contract_id()),
                        &PreimageDecryptionShare(decryption_share),
                    )
                    .await
                    .expect("DB Error");
                    dbtx.remove_entry(&OfferKey(offer.hash))
                        .await
                        .expect("DB Error");
                }
            }
            LightningOutput::Offer(offer) => {
                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcome::Offer { id: offer.id() },
                )
                .await
                .expect("DB Error");
                // TODO: sanity-check encrypted preimage size
                dbtx.insert_new_entry(&OfferKey(offer.hash), &(*offer).clone())
                    .await
                    .expect("DB Error");
            }
            LightningOutput::CancelOutgoing { contract, .. } => {
                let updated_contract_account = {
                    let mut contract_account = dbtx
                        .get_value(&ContractKey(*contract))
                        .await
                        .expect("DB error")
                        .expect("Contract exists if output is valid");

                    let outgoing_contract = match &mut contract_account.contract {
                        FundedContract::Outgoing(contract) => contract,
                        _ => {
                            panic!("Contract type was checked in validate_output");
                        }
                    };

                    outgoing_contract.cancelled = true;

                    contract_account
                };

                dbtx.insert_entry(&ContractKey(*contract), &updated_contract_account)
                    .await
                    .expect("DB Error");
            }
        }

        Ok(amount)
    }

    #[instrument(skip_all)]
    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        consensus_peers: &HashSet<PeerId>,
        dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        // Decrypt preimages
        let preimage_decryption_shares = dbtx
            .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
            .await
            .map(|res| {
                let (key, value) = res.expect("DB error");
                (key.0, (key.1, value))
            })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .into_group_map();

        let mut bad_peers = vec![];
        for (contract_id, shares) in preimage_decryption_shares {
            let peers: Vec<PeerId> = shares.iter().map(|(peer, _)| *peer).collect();
            let span = info_span!("decrypt_preimage", %contract_id);
            let _gaurd = span.enter();

            let incoming_contract = match self.get_contract_account(dbtx, contract_id).await {
                Some(ContractAccount {
                    contract: FundedContract::Incoming(incoming),
                    ..
                }) => incoming.contract,
                _ => {
                    warn!("Received decryption share for non-existent incoming contract");
                    for peer in peers {
                        dbtx.remove_entry(&AgreedDecryptionShareKey(contract_id, peer))
                            .await
                            .expect("DB Error");
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

            if valid_shares.len() < self.cfg.consensus.threshold() {
                warn!(
                    valid_shares = %valid_shares.len(),
                    shares_needed = %self.cfg.consensus.threshold(),
                    "Too few decryption shares"
                );
                continue;
            }
            debug!("Beginning to decrypt preimage");

            let contract = self
                .get_contract_account(dbtx, contract_id)
                .await
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

            let preimage_vec = match self.cfg.consensus.threshold_pub_keys.decrypt(
                valid_shares
                    .iter()
                    .map(|(peer, share)| (peer.to_usize(), &share.0)),
                &incoming_contract.encrypted_preimage.0,
            ) {
                Ok(preimage_vec) => preimage_vec,
                Err(_) => {
                    // TODO: check if that can happen even though shares are verified before
                    error!(contract_hash = %incoming_contract.hash, "Failed to decrypt preimage");
                    continue;
                }
            };

            // Delete decryption shares once we've decrypted the preimage
            dbtx.remove_entry(&ProposeDecryptionShareKey(contract_id))
                .await
                .expect("DB Error");
            for peer in peers {
                dbtx.remove_entry(&AgreedDecryptionShareKey(contract_id, peer))
                    .await
                    .expect("DB Error");
            }

            let decrypted_preimage = if preimage_vec.len() == 32
                && incoming_contract.hash == bitcoin_hashes::sha256::Hash::hash(&preimage_vec)
            {
                let preimage = Preimage(
                    preimage_vec
                        .as_slice()
                        .try_into()
                        .expect("Invalid preimage length"),
                );
                if preimage.to_public_key().is_ok() {
                    DecryptedPreimage::Some(preimage)
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
            let mut contract_account = dbtx
                .get_value(&contract_db_key)
                .await
                .expect("DB error")
                .expect("checked before that it exists");
            let mut incoming = match &mut contract_account.contract {
                FundedContract::Incoming(incoming) => incoming,
                _ => unreachable!("previously checked that it's an incoming contrac"),
            };
            incoming.contract.decrypted_preimage = decrypted_preimage.clone();
            trace!(?contract_account, "Updating contract account");
            dbtx.insert_entry(&contract_db_key, &contract_account)
                .await
                .expect("DB Error");

            // Update output outcome
            let outcome_db_key = ContractUpdateKey(out_point);
            let mut outcome = dbtx
                .get_value(&outcome_db_key)
                .await
                .expect("DB error")
                .expect("outcome was created on funding");
            let incoming_contract_outcome_preimage = match &mut outcome {
                LightningOutputOutcome::Contract {
                    outcome: ContractOutcome::Incoming(decryption_outcome),
                    ..
                } => decryption_outcome,
                _ => panic!("We are expeccting an incoming contract"),
            };
            *incoming_contract_outcome_preimage = decrypted_preimage.clone();
            dbtx.insert_entry(&outcome_db_key, &outcome)
                .await
                .expect("DB Error");
        }

        bad_peers
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&ContractUpdateKey(out_point))
            .await
            .expect("DB error")
    }

    async fn audit(&self, dbtx: &mut DatabaseTransaction<'_>, audit: &mut Audit) {
        audit
            .add_items(dbtx, &ContractKeyPrefix, |_, v| -(v.amount.msats as i64))
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                "/account",
                async |module: &Lightning, dbtx, contract_id: ContractId| -> ContractAccount {
                    module
                        .get_contract_account(dbtx, contract_id)
                        .await
                        .ok_or_else(|| ApiError::not_found(String::from("Contract not found")))
                }
            },
            api_endpoint! {
                "/offer",
                async |module: &Lightning, dbtx, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    let offer = module
                        .get_offer(dbtx, payment_hash)
                        .await
                        .ok_or_else(|| ApiError::not_found(String::from("Offer not found")))?;

                    debug!(%payment_hash, "Sending offer info");
                    Ok(offer)
                }
            },
            api_endpoint! {
                "/list_gateways",
                async |module: &Lightning, dbtx, _v: ()| -> Vec<LightningGateway> {
                    Ok(module.list_gateways(dbtx).await)
                }
            },
            api_endpoint! {
                "/register_gateway",
                async |module: &Lightning, dbtx, gateway: LightningGateway| -> () {
                    module.register_gateway(dbtx, gateway).await;
                    Ok(())
                }
            },
        ]
    }
}

impl Lightning {
    pub fn new(cfg: LightningConfig) -> Self {
        Lightning { cfg }
    }

    fn validate_decryption_share(
        &self,
        peer: PeerId,
        share: &PreimageDecryptionShare,
        message: &EncryptedPreimage,
    ) -> bool {
        self.cfg
            .consensus
            .threshold_pub_keys
            .public_key_share(peer.to_usize())
            .verify_decryption_share(&share.0, &message.0)
    }

    pub async fn get_offer(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        dbtx.get_value(&OfferKey(payment_hash))
            .await
            .expect("DB error")
    }

    pub async fn get_offers(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<IncomingContractOffer> {
        dbtx.find_by_prefix(&OfferKeyPrefix)
            .await
            .map(|res| res.expect("DB error").1)
            .collect::<Vec<IncomingContractOffer>>()
            .await
    }

    pub async fn get_contract_account(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        contract_id: ContractId,
    ) -> Option<ContractAccount> {
        dbtx.get_value(&ContractKey(contract_id))
            .await
            .expect("DB error")
    }

    pub async fn list_gateways(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<LightningGateway> {
        let stream = dbtx.find_by_prefix(&LightningGatewayKeyPrefix).await;
        stream
            .filter_map(|res| async {
                let gw = res.expect("DB error").1;
                // FIXME: actually remove from DB
                if gw.valid_until > SystemTime::now() {
                    Some(gw)
                } else {
                    None
                }
            })
            .collect::<Vec<LightningGateway>>()
            .await
    }

    pub async fn register_gateway(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        gateway: LightningGateway,
    ) {
        dbtx.insert_entry(&LightningGatewayKey(gateway.node_pub_key), &gateway)
            .await
            .expect("DB error");
    }
}

plugin_types_trait_impl!(
    LightningInput,
    LightningOutput,
    LightningOutputOutcome,
    LightningConsensusItem,
    LightningVerificationCache
);

async fn block_height(interconnect: &dyn ModuleInterconect) -> u32 {
    // This is a future because we are normally reading from a network socket. But
    // for internal calls the data is available instantly in one go, so we can
    // just block on it.
    let body = interconnect
        .call(
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            "/block_height".to_owned(),
            Default::default(),
        )
        .await
        .expect("Wallet module not present or malfunctioning!");

    serde_json::from_value(body).expect("Malformed block height response from wallet module!")
}

// TODO: upstream serde support to LDK
/// Hack to get a route hint that implements `serde` traits.
pub mod route_hints {
    use fedimint_core::encoding::{Decodable, Encodable};
    use secp256k1::PublicKey;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
    pub struct RouteHintHop {
        /// The `node_id` of the non-target end of the route
        pub src_node_id: PublicKey,
        /// The `short_channel_id` of this channel
        pub short_channel_id: u64,
        /// Flat routing fee in millisatoshis
        pub base_msat: u32,
        /// Liquidity-based routing fee in millionths of a routed amount.
        /// In other words, 10000 is 1%.
        pub proportional_millionths: u32,
        /// The difference in CLTV values between this node and the next node.
        pub cltv_expiry_delta: u16,
        /// The minimum value, in msat, which must be relayed to the next hop.
        pub htlc_minimum_msat: Option<u64>,
        /// The maximum value in msat available for routing with a single HTLC.
        pub htlc_maximum_msat: Option<u64>,
    }

    /// A list of hops along a payment path terminating with a channel to the
    /// recipient.
    #[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
    pub struct RouteHint(pub Vec<RouteHintHop>);

    impl RouteHint {
        pub fn to_ldk_route_hint(&self) -> lightning::routing::router::RouteHint {
            lightning::routing::router::RouteHint(
                self.0
                    .iter()
                    .map(|hop| lightning::routing::router::RouteHintHop {
                        src_node_id: hop.src_node_id,
                        short_channel_id: hop.short_channel_id,
                        fees: lightning::routing::gossip::RoutingFees {
                            base_msat: hop.base_msat,
                            proportional_millionths: hop.proportional_millionths,
                        },
                        cltv_expiry_delta: hop.cltv_expiry_delta,
                        htlc_minimum_msat: hop.htlc_minimum_msat,
                        htlc_maximum_msat: hop.htlc_maximum_msat,
                    })
                    .collect(),
            )
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LightningError {
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
    #[error("Only outgoing contracts support cancellation")]
    NotOutgoingContract,
    #[error("Cancellation request wasn't properly signed")]
    InvalidCancellationSignature,
}
