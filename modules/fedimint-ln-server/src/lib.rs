#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]

pub mod db;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, bail};
use bitcoin_hashes::{Hash as BitcoinHash, sha256};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseValue, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiEndpointContext, ApiVersion, CORE_CONSENSUS_VERSION,
    CoreConsensusVersion, InputMeta, ModuleConsensusVersion, ModuleInit,
    SupportedModuleApiVersions, TransactionItemAmounts, api_endpoint,
};
use fedimint_core::secp256k1::{Message, PublicKey, SECP256K1};
use fedimint_core::task::sleep;
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::{
    Amount, InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send,
    push_db_pair_items,
};
pub use fedimint_ln_common as common;
use fedimint_ln_common::config::{
    FeeConsensus, LightningClientConfig, LightningConfig, LightningConfigConsensus,
    LightningConfigPrivate,
};
use fedimint_ln_common::contracts::incoming::{IncomingContractAccount, IncomingContractOffer};
use fedimint_ln_common::contracts::{
    Contract, ContractId, ContractOutcome, DecryptedPreimage, DecryptedPreimageStatus,
    EncryptedPreimage, FundedContract, IdentifiableContract, Preimage, PreimageDecryptionShare,
    PreimageKey,
};
use fedimint_ln_common::federation_endpoint_constants::{
    ACCOUNT_ENDPOINT, AWAIT_ACCOUNT_ENDPOINT, AWAIT_BLOCK_HEIGHT_ENDPOINT, AWAIT_OFFER_ENDPOINT,
    AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT, AWAIT_PREIMAGE_DECRYPTION, BLOCK_COUNT_ENDPOINT,
    GET_DECRYPTED_PREIMAGE_STATUS, LIST_GATEWAYS_ENDPOINT, OFFER_ENDPOINT,
    REGISTER_GATEWAY_ENDPOINT, REMOVE_GATEWAY_CHALLENGE_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_ln_common::{
    ContractAccount, LightningCommonInit, LightningConsensusItem, LightningGatewayAnnouncement,
    LightningGatewayRegistration, LightningInput, LightningInputError, LightningModuleTypes,
    LightningOutput, LightningOutputError, LightningOutputOutcome, LightningOutputOutcomeV0,
    LightningOutputV0, MODULE_CONSENSUS_VERSION, RemoveGatewayRequest,
    create_gateway_remove_message,
};
use fedimint_logging::LOG_MODULE_LN;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use metrics::{LN_CANCEL_OUTGOING_CONTRACTS, LN_FUNDED_CONTRACT_SATS, LN_INCOMING_OFFER};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use threshold_crypto::poly::Commitment;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeyShare};
use tracing::{debug, error, info, info_span, trace, warn};

use crate::db::{
    AgreedDecryptionShareContractIdPrefix, AgreedDecryptionShareKey,
    AgreedDecryptionShareKeyPrefix, BlockCountVoteKey, BlockCountVotePrefix, ContractKey,
    ContractKeyPrefix, ContractUpdateKey, ContractUpdateKeyPrefix, DbKeyPrefix,
    EncryptedPreimageIndexKey, EncryptedPreimageIndexKeyPrefix, LightningAuditItemKey,
    LightningAuditItemKeyPrefix, LightningGatewayKey, LightningGatewayKeyPrefix, OfferKey,
    OfferKeyPrefix, ProposeDecryptionShareKey, ProposeDecryptionShareKeyPrefix,
};

mod metrics;

#[derive(Debug, Clone)]
pub struct LightningInit;

impl ModuleInit for LightningInit {
    type Common = LightningCommonInit;

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
                        LightningOutputOutcomeV0,
                        lightning,
                        "Contract Updates"
                    );
                }
                DbKeyPrefix::LightningGateway => {
                    push_db_pair_items!(
                        dbtx,
                        LightningGatewayKeyPrefix,
                        LightningGatewayKey,
                        LightningGatewayRegistration,
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
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        lightning,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::EncryptedPreimageIndex => {
                    push_db_pair_items!(
                        dbtx,
                        EncryptedPreimageIndexKeyPrefix,
                        EncryptedPreimageIndexKey,
                        (),
                        lightning,
                        "Encrypted Preimage Hashes"
                    );
                }
                DbKeyPrefix::LightningAuditItem => {
                    push_db_pair_items!(
                        dbtx,
                        LightningAuditItemKeyPrefix,
                        LightningAuditItemKey,
                        Amount,
                        lightning,
                        "Lightning Audit Items"
                    );
                }
            }
        }

        Box::new(lightning.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for LightningInit {
    type Module = Lightning;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 1)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        // Eagerly initialize metrics that trigger infrequently
        LN_CANCEL_OUTGOING_CONTRACTS.get();

        Ok(Lightning {
            cfg: args.cfg().to_typed()?,
            our_peer_id: args.our_peer_id(),
            server_bitcoin_rpc_monitor: args.server_bitcoin_rpc_monitor(),
        })
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let sks = threshold_crypto::SecretKeySet::random(peers.to_num_peers().degree(), &mut OsRng);
        let pks = sks.public_keys();

        peers
            .iter()
            .map(|&peer| {
                let sk = sks.secret_key_share(peer.to_usize());

                (
                    peer,
                    LightningConfig {
                        consensus: LightningConfigConsensus {
                            threshold_pub_keys: pks.clone(),
                            fee_consensus: FeeConsensus::default(),
                            network: NetworkLegacyEncodingWrapper(args.network),
                        },
                        private: LightningConfigPrivate {
                            threshold_sec_key: threshold_crypto::serde_impl::SerdeSecret(sk),
                        },
                    }
                    .to_erased(),
                )
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let (polynomial, mut sks) = peers.run_dkg_g1().await?;

        let server = LightningConfig {
            consensus: LightningConfigConsensus {
                threshold_pub_keys: PublicKeySet::from(Commitment::from(polynomial)),
                fee_consensus: FeeConsensus::default(),
                network: NetworkLegacyEncodingWrapper(args.network),
            },
            private: LightningConfigPrivate {
                threshold_sec_key: SerdeSecret(SecretKeyShare::from_mut(&mut sks)),
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<LightningConfig>()?;
        if config.private.threshold_sec_key.public_key_share()
            != config
                .consensus
                .threshold_pub_keys
                .public_key_share(identity.to_usize())
        {
            bail!("Lightning private key doesn't match pubkey share");
        }
        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<LightningClientConfig> {
        let config = LightningConfigConsensus::from_erased(config)?;
        Ok(LightningClientConfig {
            threshold_pub_key: config.threshold_pub_keys.public_key(),
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}
/// The lightning module implements an account system. It does not have the
/// privacy guarantees of the e-cash mint module but instead allows for smart
/// contracting. There exist two contract types that can be used to "lock"
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
/// These two primitives allow to integrate the federation with the wider
/// Lightning network through a centralized but untrusted (except for
/// availability) Lightning gateway server.
///
/// [Outgoing]: fedimint_ln_common::contracts::outgoing::OutgoingContract
/// [Incoming]: fedimint_ln_common::contracts::incoming::IncomingContract
#[derive(Debug)]
pub struct Lightning {
    cfg: LightningConfig,
    our_peer_id: PeerId,
    server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Lightning {
    type Common = LightningModuleTypes;
    type Init = LightningInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        let mut items: Vec<LightningConsensusItem> = dbtx
            .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
            .await
            .map(|(ProposeDecryptionShareKey(contract_id), share)| {
                LightningConsensusItem::DecryptPreimage(contract_id, share)
            })
            .collect()
            .await;

        if let Ok(block_count_vote) = self.get_block_count() {
            trace!(target: LOG_MODULE_LN, ?block_count_vote, "Proposing block count");
            items.push(LightningConsensusItem::BlockCount(block_count_vote));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: LightningConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let span = info_span!("process decryption share", %peer_id);
        let _guard = span.enter();
        trace!(target: LOG_MODULE_LN, ?consensus_item, "Processing consensus item proposal");

        match consensus_item {
            LightningConsensusItem::DecryptPreimage(contract_id, share) => {
                if dbtx
                    .get_value(&AgreedDecryptionShareKey(contract_id, peer_id))
                    .await
                    .is_some()
                {
                    bail!("Already received a valid decryption share for this peer");
                }

                let account = dbtx
                    .get_value(&ContractKey(contract_id))
                    .await
                    .context("Contract account for this decryption share does not exist")?;

                let (contract, out_point) = match account.contract {
                    FundedContract::Incoming(contract) => (contract.contract, contract.out_point),
                    FundedContract::Outgoing(..) => {
                        bail!("Contract account for this decryption share is outgoing");
                    }
                };

                if contract.decrypted_preimage != DecryptedPreimage::Pending {
                    bail!("Contract for this decryption share is not pending");
                }

                if !self.validate_decryption_share(peer_id, &share, &contract.encrypted_preimage) {
                    bail!("Decryption share is invalid");
                }

                // we save the first ordered valid decryption share for every peer
                dbtx.insert_new_entry(&AgreedDecryptionShareKey(contract_id, peer_id), &share)
                    .await;

                // collect all valid decryption shares previously received for this contract
                let decryption_shares = dbtx
                    .find_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await
                    .map(|(key, decryption_share)| (key.1, decryption_share))
                    .collect::<Vec<_>>()
                    .await;

                if decryption_shares.len() < self.cfg.consensus.threshold() {
                    return Ok(());
                }

                debug!(target: LOG_MODULE_LN, "Beginning to decrypt preimage");

                let Ok(preimage_vec) = self.cfg.consensus.threshold_pub_keys.decrypt(
                    decryption_shares
                        .iter()
                        .map(|(peer, share)| (peer.to_usize(), &share.0)),
                    &contract.encrypted_preimage.0,
                ) else {
                    // TODO: check if that can happen even though shares are verified
                    // before
                    error!(target: LOG_MODULE_LN, contract_hash = %contract.hash, "Failed to decrypt preimage");
                    return Ok(());
                };

                // Delete decryption shares once we've decrypted the preimage
                dbtx.remove_entry(&ProposeDecryptionShareKey(contract_id))
                    .await;

                dbtx.remove_by_prefix(&AgreedDecryptionShareContractIdPrefix(contract_id))
                    .await;

                let decrypted_preimage = if preimage_vec.len() == 33
                    && contract.hash
                        == sha256::Hash::hash(&sha256::Hash::hash(&preimage_vec).to_byte_array())
                {
                    let preimage = PreimageKey(
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

                debug!(target: LOG_MODULE_LN, ?decrypted_preimage);

                // TODO: maybe define update helper fn
                // Update contract
                let contract_db_key = ContractKey(contract_id);
                let mut contract_account = dbtx
                    .get_value(&contract_db_key)
                    .await
                    .expect("checked before that it exists");
                let incoming = match &mut contract_account.contract {
                    FundedContract::Incoming(incoming) => incoming,
                    FundedContract::Outgoing(_) => {
                        unreachable!("previously checked that it's an incoming contract")
                    }
                };
                incoming.contract.decrypted_preimage = decrypted_preimage.clone();
                trace!(?contract_account, "Updating contract account");
                dbtx.insert_entry(&contract_db_key, &contract_account).await;

                // Update output outcome
                let mut outcome = dbtx
                    .get_value(&ContractUpdateKey(out_point))
                    .await
                    .expect("outcome was created on funding");

                let LightningOutputOutcomeV0::Contract {
                    outcome: ContractOutcome::Incoming(incoming_contract_outcome_preimage),
                    ..
                } = &mut outcome
                else {
                    panic!("We are expecting an incoming contract")
                };
                *incoming_contract_outcome_preimage = decrypted_preimage.clone();
                dbtx.insert_entry(&ContractUpdateKey(out_point), &outcome)
                    .await;
            }
            LightningConsensusItem::BlockCount(block_count) => {
                let current_vote = dbtx
                    .get_value(&BlockCountVoteKey(peer_id))
                    .await
                    .unwrap_or(0);

                if block_count < current_vote {
                    bail!("Block count vote decreased");
                }

                if block_count == current_vote {
                    bail!("Block height vote is redundant");
                }

                dbtx.insert_entry(&BlockCountVoteKey(peer_id), &block_count)
                    .await;
            }
            LightningConsensusItem::Default { variant, .. } => {
                bail!("Unknown lightning consensus item received, variant={variant}");
            }
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b LightningInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, LightningInputError> {
        let input = input.ensure_v0_ref()?;

        let mut account = dbtx
            .get_value(&ContractKey(input.contract_id))
            .await
            .ok_or(LightningInputError::UnknownContract(input.contract_id))?;

        if account.amount < input.amount {
            return Err(LightningInputError::InsufficientFunds(
                account.amount,
                input.amount,
            ));
        }

        let consensus_block_count = self.consensus_block_count(dbtx).await;

        let pub_key = match &account.contract {
            FundedContract::Outgoing(outgoing) => {
                if u64::from(outgoing.timelock) + 1 > consensus_block_count && !outgoing.cancelled {
                    // If the timelock hasn't expired yet …
                    let preimage_hash = bitcoin_hashes::sha256::Hash::hash(
                        &input
                            .witness
                            .as_ref()
                            .ok_or(LightningInputError::MissingPreimage)?
                            .0,
                    );

                    // … and the spender provides a valid preimage …
                    if preimage_hash != outgoing.hash {
                        return Err(LightningInputError::InvalidPreimage);
                    }

                    // … then the contract account can be spent using the gateway key,
                    outgoing.gateway_key
                } else {
                    // otherwise the user can claim the funds back.
                    outgoing.user_key
                }
            }
            FundedContract::Incoming(incoming) => match &incoming.contract.decrypted_preimage {
                // Once the preimage has been decrypted …
                DecryptedPreimage::Pending => {
                    return Err(LightningInputError::ContractNotReady);
                }
                // … either the user may spend the funds since they sold a valid preimage …
                DecryptedPreimage::Some(preimage) => match preimage.to_public_key() {
                    Ok(pub_key) => pub_key,
                    Err(_) => return Err(LightningInputError::InvalidPreimage),
                },
                // … or the gateway may claim back funds for not receiving the advertised preimage.
                DecryptedPreimage::Invalid => incoming.contract.gateway_key,
            },
        };

        account.amount -= input.amount;

        dbtx.insert_entry(&ContractKey(input.contract_id), &account)
            .await;

        // When a contract reaches a terminal state, the associated amount will be
        // updated to 0. At this point, the contract no longer needs to be tracked
        // for auditing liabilities, so we can safely remove the audit key.
        let audit_key = LightningAuditItemKey::from_funded_contract(&account.contract);
        if account.amount.msats == 0 {
            dbtx.remove_entry(&audit_key).await;
        } else {
            dbtx.insert_entry(&audit_key, &account.amount).await;
        }

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(input.amount),
                fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.contract_input),
            },
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a LightningOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, LightningOutputError> {
        let output = output.ensure_v0_ref()?;

        match output {
            LightningOutputV0::Contract(contract) => {
                // Incoming contracts are special, they need to match an offer
                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
                        .ok_or(LightningOutputError::NoOffer(incoming.hash))?;

                    if contract.amount < offer.amount {
                        // If the account is not sufficiently funded fail the output
                        return Err(LightningOutputError::InsufficientIncomingFunding(
                            offer.amount,
                            contract.amount,
                        ));
                    }
                }

                if contract.amount == Amount::ZERO {
                    return Err(LightningOutputError::ZeroOutput);
                }

                let contract_db_key = ContractKey(contract.contract.contract_id());

                let updated_contract_account = dbtx.get_value(&contract_db_key).await.map_or_else(
                    || ContractAccount {
                        amount: contract.amount,
                        contract: contract.contract.clone().to_funded(out_point),
                    },
                    |mut value: ContractAccount| {
                        value.amount += contract.amount;
                        value
                    },
                );

                dbtx.insert_entry(
                    &LightningAuditItemKey::from_funded_contract(
                        &updated_contract_account.contract,
                    ),
                    &updated_contract_account.amount,
                )
                .await;

                if dbtx
                    .insert_entry(&contract_db_key, &updated_contract_account)
                    .await
                    .is_none()
                {
                    dbtx.on_commit(move || {
                        record_funded_contract_metric(&updated_contract_account);
                    });
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::Contract {
                        id: contract.contract.contract_id(),
                        outcome: contract.contract.to_outcome(),
                    },
                )
                .await;

                if let Contract::Incoming(incoming) = &contract.contract {
                    let offer = dbtx
                        .get_value(&OfferKey(incoming.hash))
                        .await
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
                    .await;

                    dbtx.remove_entry(&OfferKey(offer.hash)).await;
                }

                Ok(TransactionItemAmounts {
                    amounts: Amounts::new_bitcoin(contract.amount),
                    fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.contract_output),
                })
            }
            LightningOutputV0::Offer(offer) => {
                if !offer.encrypted_preimage.0.verify() {
                    return Err(LightningOutputError::InvalidEncryptedPreimage);
                }

                // Check that each preimage is only offered for sale once, see #1397
                if dbtx
                    .insert_entry(
                        &EncryptedPreimageIndexKey(offer.encrypted_preimage.consensus_hash()),
                        &(),
                    )
                    .await
                    .is_some()
                {
                    return Err(LightningOutputError::DuplicateEncryptedPreimage);
                }

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::Offer { id: offer.id() },
                )
                .await;

                // TODO: sanity-check encrypted preimage size
                if dbtx
                    .insert_entry(&OfferKey(offer.hash), &(*offer).clone())
                    .await
                    .is_some()
                {
                    // Technically the error isn't due to a duplicate encrypted preimage but due to
                    // a duplicate payment hash, practically it's the same problem though: re-using
                    // the invoice key. Since we can't eaily extend the error enum we just re-use
                    // this variant.
                    return Err(LightningOutputError::DuplicateEncryptedPreimage);
                }

                dbtx.on_commit(|| {
                    LN_INCOMING_OFFER.inc();
                });

                Ok(TransactionItemAmounts::ZERO)
            }
            LightningOutputV0::CancelOutgoing {
                contract,
                gateway_signature,
            } => {
                let contract_account = dbtx
                    .get_value(&ContractKey(*contract))
                    .await
                    .ok_or(LightningOutputError::UnknownContract(*contract))?;

                let outgoing_contract = match &contract_account.contract {
                    FundedContract::Outgoing(contract) => contract,
                    FundedContract::Incoming(_) => {
                        return Err(LightningOutputError::NotOutgoingContract);
                    }
                };

                SECP256K1
                    .verify_schnorr(
                        gateway_signature,
                        &Message::from_digest(*outgoing_contract.cancellation_message().as_ref()),
                        &outgoing_contract.gateway_key.x_only_public_key().0,
                    )
                    .map_err(|_| LightningOutputError::InvalidCancellationSignature)?;

                let updated_contract_account = {
                    let mut contract_account = dbtx
                        .get_value(&ContractKey(*contract))
                        .await
                        .expect("Contract exists if output is valid");

                    let outgoing_contract = match &mut contract_account.contract {
                        FundedContract::Outgoing(contract) => contract,
                        FundedContract::Incoming(_) => {
                            panic!("Contract type was checked in validate_output");
                        }
                    };

                    outgoing_contract.cancelled = true;

                    contract_account
                };

                dbtx.insert_entry(&ContractKey(*contract), &updated_contract_account)
                    .await;

                dbtx.insert_new_entry(
                    &ContractUpdateKey(out_point),
                    &LightningOutputOutcomeV0::CancelOutgoingContract { id: *contract },
                )
                .await;

                dbtx.on_commit(|| {
                    LN_CANCEL_OUTGOING_CONTRACTS.inc();
                });

                Ok(TransactionItemAmounts::ZERO)
            }
        }
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<LightningOutputOutcome> {
        dbtx.get_value(&ContractUpdateKey(out_point))
            .await
            .map(LightningOutputOutcome::V0)
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &LightningAuditItemKeyPrefix,
                // Both incoming and outgoing contracts represent liabilities to the federation
                // since they are obligations to issue notes.
                |_, v| -(v.msats as i64),
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, _v: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(Some(module.consensus_block_count(&mut dbtx).await))
                }
            },
            api_endpoint! {
                ACCOUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> Option<ContractAccount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module
                        .get_contract_account(&mut dbtx, contract_id)
                        .await)
                }
            },
            api_endpoint! {
                AWAIT_ACCOUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> ContractAccount {
                    Ok(module
                        .wait_contract_account(context, contract_id)
                        .await)
                }
            },
            api_endpoint! {
                AWAIT_BLOCK_HEIGHT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, block_height: u64| -> () {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    module.wait_block_height(block_height, &mut dbtx).await;
                    Ok(())
                }
            },
            api_endpoint! {
                AWAIT_OUTGOING_CONTRACT_CANCELLED_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> ContractAccount {
                    Ok(module.wait_outgoing_contract_account_cancelled(context, contract_id).await)
                }
            },
            api_endpoint! {
                GET_DECRYPTED_PREIMAGE_STATUS,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> (IncomingContractAccount, DecryptedPreimageStatus) {
                    Ok(module.get_decrypted_preimage_status(context, contract_id).await)
                }
            },
            api_endpoint! {
                AWAIT_PREIMAGE_DECRYPTION,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, contract_id: ContractId| -> (IncomingContractAccount, Option<Preimage>) {
                    Ok(module.wait_preimage_decrypted(context, contract_id).await)
                }
            },
            api_endpoint! {
                OFFER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> Option<IncomingContractOffer> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module
                        .get_offer(&mut dbtx, payment_hash)
                        .await)
               }
            },
            api_endpoint! {
                AWAIT_OFFER_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, payment_hash: bitcoin_hashes::sha256::Hash| -> IncomingContractOffer {
                    Ok(module
                        .wait_offer(context, payment_hash)
                        .await)
                }
            },
            api_endpoint! {
                LIST_GATEWAYS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, _v: ()| -> Vec<LightningGatewayAnnouncement> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.list_gateways(&mut dbtx).await)
                }
            },
            api_endpoint! {
                REGISTER_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Lightning, context, gateway: LightningGatewayAnnouncement| -> () {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    module.register_gateway(&mut dbtx.to_ref_nc(), gateway).await;
                    dbtx.commit_tx_result().await?;
                    Ok(())
                }
            },
            api_endpoint! {
                REMOVE_GATEWAY_CHALLENGE_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Lightning, context, gateway_id: PublicKey| -> Option<sha256::Hash> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_gateway_remove_challenge(gateway_id, &mut dbtx).await)
                }
            },
            api_endpoint! {
                REMOVE_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Lightning, context, remove_gateway_request: RemoveGatewayRequest| -> bool {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let result = module.remove_gateway(remove_gateway_request.clone(), &mut dbtx.to_ref_nc()).await;
                    match result {
                        Ok(()) => {
                            dbtx.commit_tx_result().await?;
                            Ok(true)
                        },
                        Err(err) => {
                            warn!(target: LOG_MODULE_LN, err = %err.fmt_compact_anyhow(), gateway_id = %remove_gateway_request.gateway_id, "Unable to remove gateway registration");
                            Ok(false)
                        },
                    }
                }
            },
        ]
    }
}

impl Lightning {
    fn get_block_count(&self) -> anyhow::Result<u64> {
        self.server_bitcoin_rpc_monitor
            .status()
            .map(|status| status.block_count)
            .context("Block count not available yet")
    }

    async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let peer_count = 3 * (self.cfg.consensus.threshold() / 2) + 1;

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|(.., count)| count)
            .collect::<Vec<_>>()
            .await;

        assert!(counts.len() <= peer_count);

        while counts.len() < peer_count {
            counts.push(0);
        }

        counts.sort_unstable();

        counts[peer_count / 2]
    }

    async fn wait_block_height(&self, block_height: u64, dbtx: &mut DatabaseTransaction<'_>) {
        while block_height >= self.consensus_block_count(dbtx).await {
            sleep(Duration::from_secs(5)).await;
        }
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

    async fn get_offer(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> Option<IncomingContractOffer> {
        dbtx.get_value(&OfferKey(payment_hash)).await
    }

    async fn wait_offer(
        &self,
        context: &mut ApiEndpointContext,
        payment_hash: bitcoin_hashes::sha256::Hash,
    ) -> IncomingContractOffer {
        let future = context.wait_key_exists(OfferKey(payment_hash));
        future.await
    }

    async fn get_contract_account(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        contract_id: ContractId,
    ) -> Option<ContractAccount> {
        dbtx.get_value(&ContractKey(contract_id)).await
    }

    async fn wait_contract_account(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> ContractAccount {
        // not using a variable here leads to a !Send error
        let future = context.wait_key_exists(ContractKey(contract_id));
        future.await
    }

    async fn wait_outgoing_contract_account_cancelled(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> ContractAccount {
        let future =
            context.wait_value_matches(ContractKey(contract_id), |contract| {
                match &contract.contract {
                    FundedContract::Outgoing(c) => c.cancelled,
                    FundedContract::Incoming(_) => false,
                }
            });
        future.await
    }

    async fn get_decrypted_preimage_status(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> (IncomingContractAccount, DecryptedPreimageStatus) {
        let f_contract = context.wait_key_exists(ContractKey(contract_id));
        let contract = f_contract.await;
        let incoming_contract_account = Self::get_incoming_contract_account(contract);
        match &incoming_contract_account.contract.decrypted_preimage {
            DecryptedPreimage::Some(key) => (
                incoming_contract_account.clone(),
                DecryptedPreimageStatus::Some(Preimage(sha256::Hash::hash(&key.0).to_byte_array())),
            ),
            DecryptedPreimage::Pending => {
                (incoming_contract_account, DecryptedPreimageStatus::Pending)
            }
            DecryptedPreimage::Invalid => {
                (incoming_contract_account, DecryptedPreimageStatus::Invalid)
            }
        }
    }

    async fn wait_preimage_decrypted(
        &self,
        context: &mut ApiEndpointContext,
        contract_id: ContractId,
    ) -> (IncomingContractAccount, Option<Preimage>) {
        let future =
            context.wait_value_matches(ContractKey(contract_id), |contract| {
                match &contract.contract {
                    FundedContract::Incoming(c) => match c.contract.decrypted_preimage {
                        DecryptedPreimage::Pending => false,
                        DecryptedPreimage::Some(_) | DecryptedPreimage::Invalid => true,
                    },
                    FundedContract::Outgoing(_) => false,
                }
            });

        let decrypt_preimage = future.await;
        let incoming_contract_account = Self::get_incoming_contract_account(decrypt_preimage);
        match incoming_contract_account
            .clone()
            .contract
            .decrypted_preimage
        {
            DecryptedPreimage::Some(key) => (
                incoming_contract_account,
                Some(Preimage(sha256::Hash::hash(&key.0).to_byte_array())),
            ),
            _ => (incoming_contract_account, None),
        }
    }

    fn get_incoming_contract_account(contract: ContractAccount) -> IncomingContractAccount {
        if let FundedContract::Incoming(incoming) = contract.contract {
            return IncomingContractAccount {
                amount: contract.amount,
                contract: incoming.contract,
            };
        }

        panic!("Contract is not an IncomingContractAccount");
    }

    async fn list_gateways(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningGatewayAnnouncement> {
        let stream = dbtx.find_by_prefix(&LightningGatewayKeyPrefix).await;
        stream
            .filter_map(|(_, gw)| async { if gw.is_expired() { None } else { Some(gw) } })
            .collect::<Vec<LightningGatewayRegistration>>()
            .await
            .into_iter()
            .map(LightningGatewayRegistration::unanchor)
            .collect::<Vec<LightningGatewayAnnouncement>>()
    }

    async fn register_gateway(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        gateway: LightningGatewayAnnouncement,
    ) {
        // Garbage collect expired gateways (since we're already writing to the DB)
        // Note: A "gotcha" of doing this here is that if two gateways are registered
        // at the same time, they will both attempt to delete the same expired gateways
        // and one of them will fail. This should be fine, since the other one will
        // succeed and the failed one will just try again.
        self.delete_expired_gateways(dbtx).await;

        dbtx.insert_entry(
            &LightningGatewayKey(gateway.info.gateway_id),
            &gateway.anchor(),
        )
        .await;
    }

    async fn delete_expired_gateways(&self, dbtx: &mut DatabaseTransaction<'_>) {
        let expired_gateway_keys = dbtx
            .find_by_prefix(&LightningGatewayKeyPrefix)
            .await
            .filter_map(|(key, gw)| async move { if gw.is_expired() { Some(key) } else { None } })
            .collect::<Vec<LightningGatewayKey>>()
            .await;

        for key in expired_gateway_keys {
            dbtx.remove_entry(&key).await;
        }
    }

    /// Returns the challenge to the gateway that must be signed by the
    /// gateway's private key in order for the gateway registration record
    /// to be removed. The challenge is the concatenation of the gateway's
    /// public key and the `valid_until` bytes. This ensures that the
    /// challenges changes every time the gateway is re-registered and ensures
    /// that the challenge is unique per-gateway.
    async fn get_gateway_remove_challenge(
        &self,
        gateway_id: PublicKey,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Option<sha256::Hash> {
        match dbtx.get_value(&LightningGatewayKey(gateway_id)).await {
            Some(gateway) => {
                let mut valid_until_bytes = gateway.valid_until.to_bytes();
                let mut challenge_bytes = gateway_id.to_bytes();
                challenge_bytes.append(&mut valid_until_bytes);
                Some(sha256::Hash::hash(&challenge_bytes))
            }
            _ => None,
        }
    }

    /// Removes the gateway registration record. First the signature provided by
    /// the gateway is verified by checking if the gateway's challenge has
    /// been signed by the gateway's private key.
    async fn remove_gateway(
        &self,
        remove_gateway_request: RemoveGatewayRequest,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<()> {
        let fed_public_key = self.cfg.consensus.threshold_pub_keys.public_key();
        let gateway_id = remove_gateway_request.gateway_id;
        let our_peer_id = self.our_peer_id;
        let signature = remove_gateway_request
            .signatures
            .get(&our_peer_id)
            .ok_or_else(|| {
                warn!(target: LOG_MODULE_LN, "No signature provided for gateway: {gateway_id}");
                anyhow::anyhow!("No signature provided for gateway {gateway_id}")
            })?;

        // If there is no challenge, the gateway does not exist in the database and
        // there is nothing to do
        let challenge = self
            .get_gateway_remove_challenge(gateway_id, dbtx)
            .await
            .ok_or(anyhow::anyhow!(
                "Gateway {gateway_id} is not registered with peer {our_peer_id}"
            ))?;

        // Verify the supplied schnorr signature is valid
        let msg = create_gateway_remove_message(fed_public_key, our_peer_id, challenge);
        signature.verify(&msg, &gateway_id.x_only_public_key().0)?;

        dbtx.remove_entry(&LightningGatewayKey(gateway_id)).await;
        info!(target: LOG_MODULE_LN, "Successfully removed gateway: {gateway_id}");
        Ok(())
    }
}

fn record_funded_contract_metric(updated_contract_account: &ContractAccount) {
    LN_FUNDED_CONTRACT_SATS
        .with_label_values(&[match updated_contract_account.contract {
            FundedContract::Incoming(_) => "incoming",
            FundedContract::Outgoing(_) => "outgoing",
        }])
        .observe(updated_contract_account.amount.sats_f64());
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use bitcoin_hashes::{Hash as BitcoinHash, sha256};
    use fedimint_core::bitcoin::{Block, BlockHash};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::encoding::Encodable;
    use fedimint_core::envs::BitcoinRpcConfig;
    use fedimint_core::module::registry::ModuleRegistry;
    use fedimint_core::module::{Amounts, InputMeta, TransactionItemAmounts};
    use fedimint_core::secp256k1::{PublicKey, generate_keypair};
    use fedimint_core::task::TaskGroup;
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{Amount, ChainId, Feerate, InPoint, OutPoint, PeerId, TransactionId};
    use fedimint_ln_common::config::{LightningClientConfig, LightningConfig, Network};
    use fedimint_ln_common::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer,
    };
    use fedimint_ln_common::contracts::outgoing::OutgoingContract;
    use fedimint_ln_common::contracts::{
        DecryptedPreimage, EncryptedPreimage, FundedContract, IdentifiableContract, Preimage,
        PreimageKey,
    };
    use fedimint_ln_common::{ContractAccount, LightningInput, LightningOutput};
    use fedimint_server_core::bitcoin_rpc::{IServerBitcoinRpc, ServerBitcoinRpcMonitor};
    use fedimint_server_core::{ServerModule, ServerModuleInit};
    use rand::rngs::OsRng;

    use crate::db::{ContractKey, LightningAuditItemKey};
    use crate::{Lightning, LightningInit};

    #[derive(Debug)]
    struct MockBitcoinServerRpc;

    #[async_trait::async_trait]
    impl IServerBitcoinRpc for MockBitcoinServerRpc {
        fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
            BitcoinRpcConfig {
                kind: "mock".to_string(),
                url: "http://mock".parse().unwrap(),
            }
        }

        fn get_url(&self) -> SafeUrl {
            "http://mock".parse().unwrap()
        }

        async fn get_block_count(&self) -> anyhow::Result<u64> {
            Err(anyhow::anyhow!("Mock block count error"))
        }

        async fn get_block_hash(&self, _height: u64) -> anyhow::Result<BlockHash> {
            Err(anyhow::anyhow!("Mock block hash error"))
        }

        async fn get_block(&self, _block_hash: &BlockHash) -> anyhow::Result<Block> {
            Err(anyhow::anyhow!("Mock block error"))
        }

        async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
            Err(anyhow::anyhow!("Mock feerate error"))
        }

        async fn submit_transaction(&self, _transaction: fedimint_core::bitcoin::Transaction) {
            // No-op for mock
        }

        async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
            Err(anyhow::anyhow!("Mock sync percentage error"))
        }

        async fn get_chain_id(&self) -> anyhow::Result<ChainId> {
            // Just mock something up
            Ok(ChainId(BlockHash::from_byte_array([1; 32])))
        }
    }

    const MINTS: u16 = 4;

    fn build_configs() -> (Vec<LightningConfig>, LightningClientConfig) {
        let peers = (0..MINTS).map(PeerId::from).collect::<Vec<_>>();
        let args = fedimint_server_core::ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfg = ServerModuleInit::trusted_dealer_gen(&LightningInit, &peers, &args);

        let client_cfg = ServerModuleInit::get_client_config(
            &LightningInit,
            &server_cfg[&PeerId::from(0)].consensus,
        )
        .unwrap();

        let server_cfg = server_cfg
            .into_values()
            .map(|config| {
                config
                    .to_typed()
                    .expect("Config was just generated by the same configgen")
            })
            .collect::<Vec<LightningConfig>>();

        (server_cfg, client_cfg)
    }

    fn random_pub_key() -> PublicKey {
        generate_keypair(&mut OsRng).1
    }

    #[test_log::test(tokio::test)]
    async fn encrypted_preimage_only_usable_once() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();

        let server = Lightning {
            cfg: server_cfg[0].clone(),
            our_peer_id: 0.into(),
            server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor::new(
                MockBitcoinServerRpc.into_dyn(),
                Duration::from_secs(1),
                &task_group,
            ),
        };

        let preimage = [42u8; 32];
        let encrypted_preimage = EncryptedPreimage(client_cfg.threshold_pub_key.encrypt([42; 32]));

        let hash = preimage.consensus_hash();
        let offer = IncomingContractOffer {
            amount: Amount::from_sats(10),
            hash,
            encrypted_preimage: encrypted_preimage.clone(),
            expiry_time: None,
        };
        let output = LightningOutput::new_v0_offer(offer);
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };

        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;

        server
            .process_output(
                &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                &output,
                out_point,
            )
            .await
            .expect("First time works");

        let hash2 = [21u8, 32].consensus_hash();
        let offer2 = IncomingContractOffer {
            amount: Amount::from_sats(1),
            hash: hash2,
            encrypted_preimage,
            expiry_time: None,
        };
        let output2 = LightningOutput::new_v0_offer(offer2);
        let out_point2 = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 1,
        };

        assert_matches!(
            server
                .process_output(
                    &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
                    &output2,
                    out_point2
                )
                .await,
            Err(_)
        );
    }

    #[test_log::test(tokio::test)]
    async fn process_input_for_valid_incoming_contracts() {
        let task_group = TaskGroup::new();
        let (server_cfg, client_cfg) = build_configs();
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let server = Lightning {
            cfg: server_cfg[0].clone(),
            our_peer_id: 0.into(),
            server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor::new(
                MockBitcoinServerRpc.into_dyn(),
                Duration::from_secs(1),
                &task_group,
            ),
        };

        let preimage = PreimageKey(generate_keypair(&mut OsRng).1.serialize());
        let funded_incoming_contract = FundedContract::Incoming(FundedIncomingContract {
            contract: IncomingContract {
                hash: sha256::Hash::hash(&sha256::Hash::hash(&preimage.0).to_byte_array()),
                encrypted_preimage: EncryptedPreimage(
                    client_cfg.threshold_pub_key.encrypt(preimage.0),
                ),
                decrypted_preimage: DecryptedPreimage::Some(preimage.clone()),
                gateway_key: random_pub_key(),
            },
            out_point: OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 0,
            },
        });

        let contract_id = funded_incoming_contract.contract_id();
        let audit_key = LightningAuditItemKey::from_funded_contract(&funded_incoming_contract);
        let amount = Amount { msats: 1000 };
        let lightning_input = LightningInput::new_v0(contract_id, amount, None);

        module_dbtx.insert_new_entry(&audit_key, &amount).await;
        module_dbtx
            .insert_new_entry(
                &ContractKey(contract_id),
                &ContractAccount {
                    amount,
                    contract: funded_incoming_contract,
                },
            )
            .await;

        let processed_input_meta = server
            .process_input(
                &mut module_dbtx.to_ref_nc(),
                &lightning_input,
                InPoint {
                    txid: TransactionId::all_zeros(),
                    in_idx: 0,
                },
            )
            .await
            .expect("should process valid incoming contract");
        let expected_input_meta = InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::ZERO,
            },
            pub_key: preimage
                .to_public_key()
                .expect("should create Schnorr pubkey from preimage"),
        };

        assert_eq!(processed_input_meta, expected_input_meta);

        let audit_item = module_dbtx.get_value(&audit_key).await;
        assert_eq!(audit_item, None);
    }

    #[test_log::test(tokio::test)]
    async fn process_input_for_valid_outgoing_contracts() {
        let task_group = TaskGroup::new();
        let (server_cfg, _) = build_configs();
        let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
        let mut dbtx = db.begin_transaction_nc().await;
        let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0;

        let server = Lightning {
            cfg: server_cfg[0].clone(),
            our_peer_id: 0.into(),
            server_bitcoin_rpc_monitor: ServerBitcoinRpcMonitor::new(
                MockBitcoinServerRpc.into_dyn(),
                Duration::from_secs(1),
                &task_group,
            ),
        };

        let preimage = Preimage([42u8; 32]);
        let gateway_key = random_pub_key();
        let outgoing_contract = FundedContract::Outgoing(OutgoingContract {
            hash: preimage.consensus_hash(),
            gateway_key,
            timelock: 1_000_000,
            user_key: random_pub_key(),
            cancelled: false,
        });
        let contract_id = outgoing_contract.contract_id();
        let audit_key = LightningAuditItemKey::from_funded_contract(&outgoing_contract);
        let amount = Amount { msats: 1000 };
        let lightning_input = LightningInput::new_v0(contract_id, amount, Some(preimage.clone()));

        module_dbtx.insert_new_entry(&audit_key, &amount).await;
        module_dbtx
            .insert_new_entry(
                &ContractKey(contract_id),
                &ContractAccount {
                    amount,
                    contract: outgoing_contract,
                },
            )
            .await;

        let processed_input_meta = server
            .process_input(
                &mut module_dbtx.to_ref_nc(),
                &lightning_input,
                InPoint {
                    txid: TransactionId::all_zeros(),
                    in_idx: 0,
                },
            )
            .await
            .expect("should process valid outgoing contract");

        let expected_input_meta = InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::ZERO,
            },
            pub_key: gateway_key,
        };

        assert_eq!(processed_input_meta, expected_input_meta);

        let audit_item = module_dbtx.get_value(&audit_key).await;
        assert_eq!(audit_item, None);
    }
}
